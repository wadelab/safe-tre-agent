"""The reviewer-facing bundle: export, deterministic report, offline check (M7).

*A verifiable research record that needs a bespoke web application to read is
not usable, and building one would have meant the reviewer trusting our renderer
as well as our numbers. The bundle is a directory of canonical JSON plus a
Markdown report generated from that JSON — no template a reviewer cannot
regenerate, no model anywhere near it.*

    export_bundle(record, out_dir, attestation=...) -> path
    verify_bundle_dir(path, public_key=...)        -> (ok, list of findings)

## Nothing private is written, structurally

Every file is produced from `PublicProvenance`, from `EvidenceItem`s, from the
`ReplayCertificate`, or from a manifest's `public_fields()`. The private trace
has no path into this module: `export_bundle` reads `record.provenance`,
`record.evidence` and `record.certificate`, and touches `record.trace` only for
the manifests, through `public_fields()`, which drops `PRIVATE_ONLY` whole. A
belt-and-braces sweep (`_scan_for_private`) then re-reads what was written and
fails the export if a private string from the trace appears in it — the check
that catches a leak nobody predicted, as opposed to the ones the type system
already forbids.

## The report is generated, not written

`README.md` is a pure function of the JSON beside it. Regenerating it is how a
reviewer checks it: `verify_bundle_dir` re-renders from the files and compares
bytes, so a report edited to say something the record does not support fails the
same check as an edited number.
"""

from __future__ import annotations

import json
import os
from typing import Any

from . import evidence as _evidence
from . import replay as _replay
from .research_record import (
    EvidenceItem, RecordError, ResearchRecord, canonical_json, sha256_hex,
)

REPORT = "README.md"
FILES = ("record.json", "provenance.json", "evidence.json",
         "replay_certificate.json", "software_manifest.json",
         "dataset_manifest.json", "disclosure_manifest.json",
         "attestation.json", REPORT)
# `dataset_manifest.json` and `attestation.json` are additions to the build
# plan's seven-file listing. The dataset manifest is required by milestone 6 and
# a reviewer cannot read the record without it — it carries the population
# declaration, which is the denominator no number in the bundle states for
# itself. The attestation is milestone 8's output, and leaving it outside the
# bundle would have meant the signature travelling separately from the thing it
# signs.


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _json_bytes(obj: Any) -> str:
    """Pretty, sorted, newline-terminated: canonical enough to diff by eye and
    stable enough to hash. Digests are taken over `canonical_json`, never over
    this rendering, so prettiness cannot change an identity."""
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True,
                      default=str) + "\n"


def _record_header(record: ResearchRecord) -> dict[str, Any]:
    manifests = record.trace.manifests
    return {
        "record_id": record.record_id,
        "schema_version": record.schema_version,
        "question": record.trace.question,
        "plan_ref": record.trace.plan_ref,
        "release_domain": record.trace.release_domain,
        "classification": (None if record.provenance is None
                           else record.provenance.classification.value),
        "public_bundle_digest": record.verified_digest(),
        "manifest_digests": {
            "software": manifests.software.digest(),
            "dataset": manifests.dataset.digest(),
            "disclosure": manifests.disclosure.digest(),
        },
        "files": list(FILES),
    }


def _scan_for_private(record: ResearchRecord, written: dict[str, str]) -> list[str]:
    """Every private string of the trace that reached a written file."""
    findings = []
    for name, text in sorted(written.items()):
        for stage in record.trace.stages:
            for level in stage.excluded_levels:
                if level and level in text:
                    findings.append(f"{name}: excluded level {level!r}")
            if stage.message and stage.message in text:
                findings.append(f"{name}: a stage's private message")
            for finding in stage.findings:
                detail = str(finding.get("detail", ""))
                if detail and detail in text:
                    findings.append(f"{name}: a stage's private finding detail")
        if record.trace.user and record.trace.user in text:
            findings.append(f"{name}: the executing user's identity")
    return findings


def export_bundle(record: ResearchRecord, out_dir: str,
                  attestation: dict[str, Any] | None = None,
                  *, allow_expected_levels: tuple[str, ...] = ()) -> str:
    """Write the public bundle. Returns the directory.

    `allow_expected_levels` names category values the COMMITTED plan already
    states in public — a plan may legitimately filter on a named level, and the
    private-string sweep would otherwise flag the plan for quoting itself. It
    is a narrow escape hatch and it is explicit: nothing is waived silently.
    """
    if record.provenance is None:
        raise RecordError("a bundle needs compiled public provenance")
    record.validate_record()

    manifests = record.trace.manifests
    payload = {
        "record.json": _json_bytes(_record_header(record)),
        "provenance.json": _json_bytes(json.loads(record.provenance.canonical())),
        "evidence.json": _json_bytes(
            [json.loads(canonical_json(e.model_dump(mode="json")))
             for e in record.evidence]),
        "replay_certificate.json": _json_bytes(
            None if record.certificate is None
            else json.loads(canonical_json(record.certificate.model_dump(mode="json")))),
        "software_manifest.json": _json_bytes(manifests.software.public_fields()),
        "dataset_manifest.json": _json_bytes(manifests.dataset.public_fields()),
        "disclosure_manifest.json": _json_bytes(manifests.disclosure.public_fields()),
        "attestation.json": _json_bytes(attestation),
    }
    payload[REPORT] = render_report(record)

    leaks = [f for f in _scan_for_private(record, payload)
             if not any(level in f for level in allow_expected_levels)]
    if leaks:
        raise RecordError(
            "refusing to export: private trace content reached the public "
            "bundle — " + "; ".join(sorted(set(leaks))))

    os.makedirs(out_dir, exist_ok=True)
    for name, text in payload.items():
        _write(os.path.join(out_dir, name), text)
    return out_dir


# --------------------------------------------------------------------------- #
# the report                                                                  #
# --------------------------------------------------------------------------- #

def _describe_node(node: dict[str, Any]) -> str:
    params = node.get("public_parameters", {})
    if node.get("stage_type") == "model":
        terms = ", ".join(params.get("terms", []))
        return (f"{params.get('tool', 'model')} ({params.get('family', '?')}) — "
                f"`{params.get('response', '?')} ~ {terms}` on `{params.get('dataset', '?')}`")
    measure = params.get("measure") or {}
    by = ", ".join(params.get("group_by", [])) or "no breakdown"
    return (f"{measure.get('fn', 'aggregate')} of `{measure.get('column', '?')}` "
            f"on `{params.get('dataset', '?')}`, by {by}")


def _evidence_table(rows: list[dict[str, Any]]) -> list[str]:
    """The evidence table, rendered from the JSON file.

    Each row is re-validated through `EvidenceItem` before it is rendered, so
    the report cannot be made to display something that is not a well-formed
    evidence item — and `evidence.render` stays the single renderer, rather
    than the bundle growing a second one that could disagree with it.
    """
    lines = ["| evidence | kind | about | value | stage | figure |",
             "|---|---|---|---|---|---|"]
    for row in rows:
        item = EvidenceItem(**row)
        about = ", ".join(f"{k}={v}" for k, v in sorted(item.keys.items())) or "—"
        lines.append(
            f"| `{item.evidence_id}` | {item.kind} | {about} | "
            f"{_evidence.render(item)} | `{item.source_stage}` | "
            f"{item.manuscript_ref or '—'} |")
    return lines


_CLASSIFICATION_PROSE = {
    "TRE_PRECOMMITTED": (
        "The plan governing every released stage was committed to this TRE's "
        "append-only audit chain **before** those stages observed any protected "
        "result. This is a machine property of the recorded execution, derived "
        "from event order and not asserted by the researcher or the model.\n\n"
        "It is deliberately narrower than scientific pre-registration. It shows "
        "that this execution did not choose its analysis after seeing its own "
        "protected intermediates. It cannot show that the researcher had never "
        "seen related data or results before the session opened."),
    "EXPLORATORY_POSTHOC": (
        "At least one released stage was **not** governed by a plan committed "
        "before it ran. The record labels the analysis exploratory. That is not "
        "a defect — exploration is legitimate — but a reader should not treat "
        "these results as confirmatory."),
}


def render_report(record: ResearchRecord) -> str:
    """`README.md` for a record in hand."""
    manifests = record.trace.manifests
    return render_report_from_public(
        record_id=record.record_id,
        provenance=json.loads(record.provenance.canonical()),   # type: ignore[union-attr]
        evidence=[json.loads(canonical_json(e.model_dump(mode="json")))
                  for e in record.evidence],
        certificate=(None if record.certificate is None else
                     json.loads(canonical_json(record.certificate.model_dump(mode="json")))),
        software=manifests.software.public_fields(),
        dataset=manifests.dataset.public_fields(),
        disclosure=manifests.disclosure.public_fields())


def render_report_from_public(*, record_id: str, provenance: dict[str, Any],
                              evidence: list[dict[str, Any]],
                              certificate: dict[str, Any] | None,
                              software: dict[str, Any], dataset: dict[str, Any],
                              disclosure: dict[str, Any]) -> str:
    """`README.md`, as a pure function of the JSON files in a bundle.

    Takes the FILES rather than the record, so that regenerating the report is
    something a reviewer can actually do: they hold the public JSON and nothing
    else, and if this function needed the private trace then "regenerate it and
    compare bytes" would have been advice only the custodian could follow.
    `verify_bundle_dir` takes them up on it.

    Deterministic and template-free. The section order is the build plan's, and
    the last section is the one that matters most — a report that only listed
    what was verified would be read as a claim that nothing else needed to be.
    """
    out: list[str] = []
    add = out.append

    add(f"# Verifiable research record `{record_id}`")
    add("")
    add("Generated deterministically from the JSON files in this directory. "
        "No language model produced any part of it; regenerate it with "
        "`safetre.vrr_bundle.render_report` and compare bytes.")
    add("")

    add("## 1. Scientific question")
    add("")
    add(f"> {provenance['question']}")
    add("")
    if provenance.get("plan_ref"):
        add(f"Committed analysis plan: `{provenance['plan_ref']}`")
        add("")
        plan = provenance.get("committed_plan") or {}
        for stage in plan.get("stages", []):
            add(f"- `{stage['id']}` — {stage['sub_question']}")
        add("")

    add("## 2. Analysis status")
    add("")
    add(f"**{provenance['classification']}**")
    add("")
    add(_CLASSIFICATION_PROSE.get(provenance['classification'], ""))
    add("")

    add("## 3. Data provenance")
    add("")
    add(f"- Study: **{dataset['logical_name']}**")
    add(f"- Snapshot: `{dataset['snapshot_id']}`")
    add(f"- Population: {dataset['population']}")
    add(f"- Custodian: {dataset['custodian']}")
    add(f"- Views available to the analysis: {', '.join(f'`{v}`' for v in dataset['views'])}")
    add(f"- Snapshot commitment: `{dataset['snapshot_commitment']}`")
    add("")
    add("The snapshot commitment is **keyed**. It binds the custodian to the "
        "exact tables this record was computed over, and only the custodian can "
        "open it. It is not something a reader can verify, and this document "
        "does not ask them to treat it as if it were.")
    add("")

    add("## 4. Software and policy provenance")
    add("")
    add(f"- Package version: `{software['package_version']}`")
    add(f"- Repository commit: `{software['repository_commit'] or 'unrecorded'}`")
    add(f"- Lockfile digest: `{software['lockfile_digest'] or 'unrecorded'}`")
    add(f"- Procedure registry digest: `{software['procedure_registry_digest']}`")
    add(f"- Catalogue digest: `{software['catalogue_digest']}`")
    add(f"- Policy digest: `{software['policy_digest']}`")
    add(f"- Public tool manifest: `{software['tool_manifest_digest']}`")
    add(f"- External output checker: `{software['external_checker']}`")
    add("")

    add("## 5. Public computational provenance")
    add("")
    add("One node per stage that carries released evidence. Stages that "
        "released nothing are **absent by construction** — their presence would "
        "publish the gateway's verdict on a cohort, which is the question the "
        "gateway's single canonical refusal exists to refuse.")
    add("")
    for node in provenance.get("nodes", []):
        add(f"### `{node['stage_id']}`")
        add("")
        add(f"- {_describe_node(node)}")
        add(f"- Classification: `{node['classification']}`")
        add(f"- Replay class: `{node['replay_class']}`")
        if node.get("input_refs"):
            add(f"- Depends on: {', '.join(f'`{d}`' for d in node['input_refs'])}")
        for artifact in node.get("artifacts", []):
            shape = artifact.get("shape")
            size = f"{shape[0]}x{shape[1]}" if shape else "—"
            add(f"- Released `{artifact['artifact_id']}` ({size}): "
                f"`{artifact['commitment']}`")
        add("")

    add("## 6. Released evidence")
    add("")
    if evidence:
        out.extend(_evidence_table(evidence))
    else:
        add("No evidence was released.")
    add("")
    add("Each commitment in section 5 is a plain SHA-256 over the canonical "
        "rendering of a table that was released, so a reader can recompute it "
        "from the values above.")
    add("")

    add("## 7. Disclosure and privacy statement")
    add("")
    add(f"- Minimum cell size: **{disclosure['min_cell_size']}**")
    add(f"- Counts rounded to the nearest: **{disclosure['counts_rounded_to_nearest']}**")
    add(f"- Output checker: `{disclosure['vetter']}`")
    add(f"- Policy digest: `{disclosure['policy_digest']}`")
    add(f"- Controls in force: {', '.join(f'`{c}`' for c in disclosure['controls'])}")
    add("")
    add("This public record is itself a disclosure surface, and is treated as "
        "one. Every field in it carries a disclosure class; the private "
        "execution trace — including what the gateway refused, why, and any "
        "category a data-sighted contingency excluded — stays inside the "
        "safepod and is not in this bundle in any form, not even as a hash.")
    add("")

    add("## 8. Replay result")
    add("")
    if certificate is None:
        add("No replay was attempted for this record.")
    else:
        add(f"**{certificate['outcome']}** (certificate `{certificate['certificate_id']}`)")
        add("")
        add(certificate['detail'])
        add("")
        add("Semantics the replay had to match exactly:")
        add("")
        for key, value in sorted(certificate['replay_semantics'].items()):
            add(f"- `{key}` = `{value}`")
        add("")
        if certificate['stages']:
            add("| stage | artifact | reproduced |")
            add("|---|---|---|")
            for row in certificate['stages']:
                add(f"| `{row['stage_id']}` | `{row['artifact_id']}` | "
                    f"{'yes' if row['reproduced'] else 'NO'} |")
            add("")
    add("")

    add("## 9. What is and is not verified")
    add("")
    add("Verified mechanically by this bundle:")
    add("")
    add("- that the released numbers are the numbers the recorded computation "
        "produced, and that re-running the committed plan over the attested "
        "snapshot under the recorded semantics reproduces them byte for byte;")
    add("- that every reported number traces to a stage and an audit row;")
    add("- that the pre-specification label follows from audit event order "
        "rather than from anybody's say-so;")
    add("- that the bundle has not been altered since it was signed, if an "
        "attestation is present and you hold the custodian's public key.")
    add("")
    add("**Not** verified, and left to the reader's judgement or the "
        "custodian's word:")
    add("")
    for caveat in ((certificate or {}).get("not_verified") or _replay.NOT_VERIFIED):
        add(f"- {caveat}")
    add("")
    add("Machine verification is not scientific validity. A record can replay "
        "perfectly and answer the wrong question.")
    add("")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# offline check                                                               #
# --------------------------------------------------------------------------- #

def verify_bundle_dir(path: str, public_key: bytes | None = None) -> tuple[bool, list[str]]:
    """Check an exported bundle from the files alone. Returns (ok, findings).

    This is the reviewer's side of the record, and it deliberately reads only
    what is in the directory: the evidence values, the provenance, the
    certificate and the attestation. It re-derives every digest it checks
    rather than comparing the ones the files assert about themselves, because a
    tamper that updates a file also updates the digest the file states.
    """
    from . import attestation as _attestation

    findings: list[str] = []

    def load(name: str) -> Any:
        with open(os.path.join(path, name), encoding="utf-8") as fh:
            return json.load(fh)

    missing = [f for f in FILES if not os.path.exists(os.path.join(path, f))]
    if missing:
        return False, [f"missing file(s): {', '.join(missing)}"]

    header = load("record.json")
    provenance = load("provenance.json")
    evidence = load("evidence.json")
    certificate = load("replay_certificate.json")
    block = load("attestation.json")

    recomputed = sha256_hex(canonical_json({
        "record_id": header["record_id"],
        "schema_version": header["schema_version"],
        "provenance": provenance,
        "evidence": evidence,
    }))
    if recomputed != header.get("public_bundle_digest"):
        findings.append(
            "the public bundle digest in record.json is not the digest of the "
            "provenance and evidence beside it")

    if certificate is not None:
        if certificate.get("record_digest") != recomputed:
            findings.append(
                "the replay certificate binds to a different record than the "
                "one in this bundle (stale or swapped certificate)")
        if certificate.get("outcome") != _replay.REPRODUCED:
            findings.append(
                f"the replay outcome is {certificate.get('outcome')!r}, not "
                f"{_replay.REPRODUCED}")
    else:
        findings.append("no replay certificate in this bundle")

    for name, key in (("software_manifest.json", "software"),
                      ("dataset_manifest.json", "dataset"),
                      ("disclosure_manifest.json", "disclosure")):
        # `public_fields()` drops nothing from these three — every field of all
        # three manifests is PUBLIC or OPAQUE_ATTESTATION — so the digest a
        # reviewer recomputes here is the digest the attestation covers.
        stated = (header.get("manifest_digests") or {}).get(key)
        actual = sha256_hex(canonical_json(load(name)))
        if stated != actual:
            findings.append(f"{name} does not match the digest record.json states")

    if block:
        payload = block.get("payload") or {}
        if payload.get("public_bundle_digest") != recomputed:
            findings.append("the attestation covers a different bundle digest")
        digest = sha256_hex(canonical_json(payload))
        if block.get("bundle_digest") != digest:
            findings.append("the attestation's bundle digest is not its payload's")
        key = public_key if public_key is not None else bytes.fromhex(
            block.get("public_key", ""))
        if not _attestation.verify_bundle(digest, block.get("signature", ""), key):
            findings.append("the attestation signature does not verify")
    else:
        findings.append("this bundle carries no attestation")

    # Regenerate the report from the JSON beside it and compare bytes. This is
    # the check that makes the report trustworthy at all: a Markdown file a
    # reviewer reads but cannot re-derive is prose asserting things about the
    # data, and a record whose narrative is unverifiable is the thing D9 exists
    # to replace.
    with open(os.path.join(path, REPORT), encoding="utf-8") as fh:
        report = fh.read()
    try:
        regenerated = render_report_from_public(
            record_id=header["record_id"], provenance=provenance,
            evidence=evidence, certificate=certificate,
            software=load("software_manifest.json"),
            dataset=load("dataset_manifest.json"),
            disclosure=load("disclosure_manifest.json"))
    except (KeyError, TypeError, ValueError) as exc:
        findings.append(f"the report cannot be regenerated from the JSON: {exc}")
    else:
        if regenerated != report:
            findings.append(
                "README.md is not what this bundle's JSON renders to; the "
                "report has been edited or the JSON has")

    return not findings, findings


__all__ = ["FILES", "REPORT", "export_bundle", "render_report", "verify_bundle_dir"]
