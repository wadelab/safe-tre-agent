"""The adversaries a published research record faces, and the oracle they are
scored against (R12; corpus in `redteam/vrr_attacks.yaml`).

Every adversary here is handed one thing: the exported bundle, as a mapping of
filename to text. Not the record object, not the trace, not the service — the
directory, which is what a reviewer, a journal, a co-author or anyone downstream
actually holds. If a fact about the protected data can be recovered from that,
the record disclosed it, whatever the compiler intended.

The oracle is built from the ROW-LEVEL tables and the private trace, in
`oracle_for`. That is R12's rule and it matters more here than anywhere: asking
"did the disclosure classification drop the field" scores the mechanism, and the
mechanism is the thing under test. Asking "is the withheld category name
recoverable from these nine files" scores the outcome.

Two adversaries are worth reading before the rest.

`declared_topology` is the one that found #109. Every other probe searches the
bundle for a secret; this one COMBINES two things the bundle publishes, each
harmless alone — the committed plan and the list of provenance nodes — and takes
the set difference to recover the gateway's per-stage verdict. Nothing in the
paired-trace noninterference tests could see it, because those hold the approved
evidence fixed and so fix the node set; the channel only exists relative to a
second published object.

`hash_dictionary` is the Glass Safe as a probe rather than an assertion. It scrapes
every commitment-shaped string out of the bundle and brute-forces each against
the domains a private value in this system actually inhabits: donor counts, the
Booleans a branch can take, and every category value in the public catalogue. A
raw content hash of any of those is a lookup table, and this is the lookup.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable

from safetre import dataset as _dataset
from safetre.research_record import canonical_json

# A commitment as written into a bundle: `scheme:hex`. Scraped rather than read
# from a known field, because the point is to find one somewhere nobody meant to
# put it.
_COMMITMENT = re.compile(r"\b(sha256|hmac-sha256/vrr-v1):([0-9a-f]{64})\b")

# Plausible donor counts for a suppressed cell. The threshold is single digits,
# so an attacker needs almost no range — the width here is generosity, not
# necessity.
_COUNT_DOMAIN = tuple(range(0, 500))


def _text(bundle: dict[str, str]) -> str:
    return "\n".join(bundle[name] for name in sorted(bundle))


def _json(bundle: dict[str, str], name: str) -> Any:
    try:
        return json.loads(bundle[name])
    except (KeyError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# the oracle                                                                  #
# --------------------------------------------------------------------------- #

def oracle_for(run: Any, trace: Any, tables: dict[str, Any]) -> dict[str, Any]:
    """What is true and withheld, computed independently of the record.

    `run` and `trace` say what the gateway did; `tables` are the unvetted rows,
    so the counts here are the real ones rather than the rounded ones a release
    would have carried. An adversary that recovers any of these from the bundle
    has been handed something the gateway refused.
    """
    refused = [sr.id for sr in run.stages if sr.status not in ("released", "redacted")]
    released = [sr.id for sr in run.stages if sr.status in ("released", "redacted")]
    excluded = sorted({lv for st in trace.stages for lv in st.excluded_levels})

    # The true, unrounded size of every excluded group, straight from the rows.
    #
    # No dtype test. The first version guarded on `dtype == object`, and pandas 3
    # gives string columns the `str` dtype, so the guard was always False, the
    # counts were always empty and the `subthreshold_counts` probe was a no-op
    # for every scenario while reporting a clean pass. An oracle that quietly
    # knows nothing is worse than no oracle: it makes the suite look green.
    true_counts: dict[str, int] = {}
    people = tables.get("people")
    if people is not None:
        for level in excluded:
            for column in people.columns:
                try:
                    hits = int((people[column] == level).sum())
                except (TypeError, ValueError):
                    continue
                if hits:
                    true_counts[level] = hits
                    break

    return {
        "declared_stages": [sr.id for sr in run.stages],
        "declared_stage_count": len(run.stages),
        "released_stages": released,
        "refused_stages": refused,
        "excluded_levels": excluded,
        "true_group_sizes": true_counts,
        "selection_bits": sum(st.selection_bits for st in trace.stages),
        "private_messages": [st.message for st in trace.stages if st.message],
        "private_findings": [str(f.get("detail", "")) for st in trace.stages
                             for f in st.findings if f.get("detail")],
        "analyst": trace.user,
    }


# --------------------------------------------------------------------------- #
# the adversaries                                                             #
# --------------------------------------------------------------------------- #

def declared_topology(bundle: dict[str, str], oracle: dict[str, Any]) -> list[str]:
    """Recover the gateway's per-stage verdict by comparing two published things.

    Finding #109. The bundle publishes a node per evidence-bearing stage; if it
    also publishes the declared plan, the difference is the refused set. Any
    other route to the declared stage COUNT does the same job, so the count is
    hunted for too — in the certificate's prose, which used to say how many
    stages it re-ran, and anywhere else a number that size appears as a claim
    about the plan.
    """
    learned = []
    provenance = _json(bundle, "provenance.json") or {}
    published = {n.get("stage_id") for n in provenance.get("nodes") or []}

    plan = provenance.get("committed_plan")
    if plan:
        declared = {s.get("id") for s in plan.get("stages") or []}
        inferred = sorted(d for d in declared - published if d)
        if inferred:
            learned.append(
                f"the refused stages {inferred} — by taking the published plan's "
                f"stage set minus the provenance nodes")
        elif declared:
            learned.append("the full declared stage set, so the refused set is "
                           "the difference from the node list")

    # a refused stage named anywhere at all
    text = _text(bundle)
    for stage_id in oracle["refused_stages"]:
        if stage_id and re.search(rf"\b{re.escape(stage_id)}\b", text):
            learned.append(f"the identifier of refused stage {stage_id!r}")

    # the declared count, stated rather than inferred
    declared_count = oracle["declared_stage_count"]
    if declared_count != len(published):
        for match in re.finditer(r"(\d+)\s+(?:exactly-replayable\s+)?stage", text):
            if int(match.group(1)) == declared_count:
                learned.append(f"the declared stage count ({declared_count}), "
                               f"which differs from the {len(published)} published")
                break
    return learned


def withheld_categories(bundle: dict[str, str], oracle: dict[str, Any]) -> list[str]:
    """Any category the gateway suppressed, by name."""
    text = _text(bundle)
    return [f"the withheld category {level!r}" for level in oracle["excluded_levels"]
            if level and level in text]


# Opaque identifiers, stripped before any numeric search. A 64-character digest
# contains a "6" somewhere in almost every bundle ever written, and an adversary
# who has to guess which 6 in a hash is the answer has learned nothing. Removing
# them first is what makes a numeric probe mean something: the alternative is a
# probe that fires on every scenario (useless) or one restricted so tightly it
# fires on none (worse, because it looks like a pass).
_OPAQUE = re.compile(r"\b(?:[0-9a-f]{16,}|(?:ev|rc|vrr)-[0-9a-f]{8,})\b")


def subthreshold_counts(bundle: dict[str, str], oracle: dict[str, Any]) -> list[str]:
    """The true, unrounded size of a suppressed group, stated anywhere.

    Every file, not just the JSON: prose discloses as well as data, and the first
    version of this probe missed a planted count in `README.md`.
    """
    learned = []
    for name in sorted(bundle):
        text = _OPAQUE.sub(" ", bundle[name])
        for level, size in oracle["true_group_sizes"].items():
            if re.search(rf"(?<![\d.]){size}(?![\d.])", text):
                learned.append(f"a literal {size} in {name}, the true size of "
                               f"withheld group {level!r}")
    return learned


def hash_dictionary(bundle: dict[str, str], oracle: dict[str, Any]) -> list[str]:
    """Brute-force every commitment in the bundle over the low-entropy domains.

    The Glass Safe. A commitment is only hiding if its preimage is hard to
    guess, and the private values this system needs to bind are counts, Booleans
    and category names — domains an attacker enumerates in milliseconds. If any
    published commitment is an unkeyed hash over one of those, this finds the
    value.
    """
    text = _text(bundle)
    published = {f"{scheme}:{digest}" for scheme, digest in _COMMITMENT.findall(text)}
    if not published:
        return []

    guesses: list[Any] = list(_COUNT_DOMAIN) + [True, False, None]
    try:
        catalogue = _dataset.active().catalogue()
    except Exception:                                   # nosec B110 - no dataset active
        catalogue = {}
    for info in catalogue.values():
        for domain in (info.get("dims") or {}).values():
            if isinstance(domain, (list, tuple, set)):
                guesses.extend(domain)
    guesses.extend(oracle["excluded_levels"])
    guesses.extend(oracle["true_group_sizes"].values())

    learned = []
    for guess in guesses:
        # every shape a caller might commit a bare private value in
        for payload in (guess, {"value": guess}, [guess],
                        {"excluded": [guess]}, {"suppressed_cells": guess}):
            digest = hashlib.sha256(canonical_json(payload).encode()).hexdigest()
            if f"sha256:{digest}" in published:
                learned.append(f"the preimage {guess!r} of a published commitment, "
                               "by dictionary attack over a low-entropy domain")
    return learned


def private_prose(bundle: dict[str, str], oracle: dict[str, Any]) -> list[str]:
    """The gateway's own words about why it refused, and who was asking."""
    text = _text(bundle)
    learned = []
    for message in oracle["private_messages"]:
        if message and message in text:
            learned.append("a stage's private refusal message")
    for detail in oracle["private_findings"]:
        if detail and detail in text:
            learned.append(f"a private finding detail: {detail[:48]!r}")
    if oracle["analyst"] and oracle["analyst"] in text:
        learned.append(f"the analyst's identity ({oracle['analyst']!r})")
    return learned


def selection_spend(bundle: dict[str, str], oracle: dict[str, Any]) -> list[str]:
    """How much data-sighted selection the plan bought.

    The bit count is the number of levels the privileged probe found sparse, so
    publishing it publishes how many categories fell below the threshold.
    """
    bits = oracle["selection_bits"]
    if not bits:
        return []
    text = _text(bundle)
    if re.search(rf"selection[^\n]*?(?<!\d){bits}(?!\d)", text, re.I) \
            or "selection_bits" in text:
        return [f"the selection budget spent ({bits} bit(s)), and so how many "
                "categories the probe found sparse"]
    return []


def correctness_badge(bundle: dict[str, str], oracle: dict[str, Any]) -> list[str]:
    """Not a disclosure — an overclaim. The Alchemist and the Peacock.

    A record that replays exactly and answers the wrong question must not be
    handed anything a reader can quote as a correctness claim, and the five
    assurance dimensions must not be collapsed into one.
    """
    upper = _text(bundle).upper()
    # Word boundaries, because the first version of this probe reported every
    # bundle as claiming `PROVEN` — the match was inside "DATA PROVENANCE". A
    # red-team probe that cries wolf on the benign scenario is worse than none:
    # the next real finding arrives in a column of noise.
    learned = [f"a correctness claim ({badge!r})" for badge in
               ("SCIENTIFICALLY VALID", "SCIENTIFICALLY_VALID", "IS VALID",
                "IS CORRECT", "PROVEN", "PROVES", "CONCLUSION SUPPORTED")
               if re.search(rf"(?<![A-Z]){re.escape(badge)}(?![A-Z])", upper)]
    certificate = _json(bundle, "replay_certificate.json") or {}
    if certificate.get("outcome") in ("VERIFIED", "OK", "PASS"):
        learned.append(f"a generic verification status "
                       f"({certificate['outcome']!r}) covering every dimension")
    report = bundle.get("README.md", "")
    if report and "DATA_SNAPSHOT_ATTESTED" in report \
            and "not established" not in report:
        learned.append("an implied claim that the data snapshot is attested")
    return learned


ADVERSARIES: dict[str, Callable[[dict[str, str], dict[str, Any]], list[str]]] = {
    "declared_topology": declared_topology,
    "withheld_categories": withheld_categories,
    "subthreshold_counts": subthreshold_counts,
    "hash_dictionary": hash_dictionary,
    "private_prose": private_prose,
    "selection_spend": selection_spend,
    "correctness_badge": correctness_badge,
}


def run_adversaries(bundle: dict[str, str], oracle: dict[str, Any]) -> dict[str, list[str]]:
    return {name: probe(bundle, oracle) for name, probe in ADVERSARIES.items()}


__all__ = ["ADVERSARIES", "oracle_for", "run_adversaries"]
