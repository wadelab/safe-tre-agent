"""Generate the inside-analyst plan deck: the proposed next research phase,
explained simply.

A plain-language concept deck for moving the AI from outside the TRE (where it
only formats requests) to an analyst working inside the boundary, with every
release still passing the existing safe-outputs gateway. This is a PLAN deck
(precise version: docs/inside-analyst.md); only phase 0 is built, and it names
no model or provider.

No screenshots are needed, so it regenerates anywhere:

    uv run --group decks python scripts/make_inside_analyst_deck.py

The output lands in ./artifacts and is gitignored like the other full decks;
committing it (as the .ppt explainers are) is a deliberate separate decision.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from make_decks import (  # noqa: E402
    AMBER, BLUE, GREEN, GREY, SLIDE_H, SLIDE_W,
    bullets_slide, table_slide, title_slide,
)
from pptx import Presentation  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def build_inside_analyst(out: str) -> None:
    prs = Presentation()
    prs.slide_width = SLIDE_W
    prs.slide_height = SLIDE_H

    title_slide(prs, "An analyst inside the room",
                "A plan: from safe single queries to safe automated analysis. "
                "Phases 0-2 and phase 3's core are built (precise version: docs/inside-analyst.md).")

    bullets_slide(prs, "Where we are today", [
        "A library holds everyone's diaries. You may never read one — you may only ask about",
        "   GROUPS, and a strict librarian checks every answer before it leaves.",
        "Today's AI helper stands OUTSIDE the library: it turns your English into the official",
        "   request form, one question at a time. It never sees any data.",
        "That was the right first system: the helper is untrusted by design, and the rulebook",
        "   does not care who is asking.",
        "But it means all the analytical thinking still happens outside, by hand.",
    ])

    bullets_slide(prs, "The limitation", [
        "Real research is not one question. 'Is late-night phone use linked to gambling?' needs",
        "   many queries, several data sources, statistical models, and follow-ups on what they show.",
        "Every round trip goes through the human — slow, and the hard statistical judgement is unassisted.",
        "The more work that can happen INSIDE the room, the more valuable the analysis —",
        "   and, done right, the more checkable.",
    ])

    bullets_slide(prs, "The idea: an analyst inside", [
        "Put an AI statistician inside the reading room, next to the data.",
        "It plans analyses, runs many queries, fits models, follows up — like consulting an expert",
        "   who has read everything, but is bound by strict rules on what they may repeat outside.",
        "You ask a research question; you get back an evidence dossier of checked, released",
        "   summaries — or an honest 'that cannot be answered, and here is why'.",
    ], accent=GREEN)

    bullets_slide(prs, "The one rule that keeps it safe", [
        "Nothing reaches you except through the SAME gateway that checks every query today.",
        "The analyst's working notes never leave the room — free text out of a model that has",
        "   seen the rows is a channel no checker can bound, so it is simply never released.",
        "The prose answer you read is written by a second AI, outside, that has seen ONLY the",
        "   released numbers. Every figure in the narrative traces to a vetted release.",
        "So the safety argument does not change shape: released = a function of vetted summaries.",
    ], accent=GREEN)

    bullets_slide(prs, "The surprisingly buildable first version", [
        "An analyst that only ever reads RELEASED answers is safe by construction —",
        "   informationally it stands on the public side of the gateway, exactly like you.",
        "Same query budget, same differencing rules, same audit log as a human analyst.",
        "Most of the value arrives here: multi-query, multi-source, follow-ups, honest refusals.",
        "This version needs agent scaffolding, not new safety machinery — it is the near-term build.",
    ], accent=GREEN)

    bullets_slide(prs, "The hard research problem, honestly", [
        "An analyst who HAS seen raw data can leak by CHOOSING: which of seven analyses to",
        "   report, which groups to compare — each choice conditioned on the data carries information.",
        "The same behaviour, done innocently, is p-hacking at machine speed.",
        "One answer serves both: the analysis plan is locked, and logged, BEFORE the data are touched.",
        "Deviating is refused — or spent from a small, declared adaptivity budget.",
        "Leak-proofing and statistical rigour turn out to be the same control.",
    ], accent=AMBER)

    bullets_slide(prs, "Proof without seeing the numbers", [
        "Every stage of an analysis is stamped into the existing tamper-evident audit chain.",
        "Every release is already reproducible bit-for-bit from its released ingredients —",
        "   a property the test suite enforces today; each stage gets the same treatment.",
        "So the system can show you: 'this analysis happened, in this order, every check passed,",
        "   and an independent replay agrees' — without a single raw value leaving the room.",
        "That is what 'proof of truth' can honestly mean when the room itself is the trust anchor.",
    ])

    bullets_slide(prs, "Keeping it local", [
        "The inside analyst should be an open-weights model on our own hardware, inside the",
        "   environment — no data sent to anyone's cloud, ever.",
        "Orchestrating a small fixed menu of registered statistical procedures is far easier than",
        "   open-ended coding — which is what makes a modest local model plausible: a 120B-class",
        "   open-weight mixture-of-experts model runs ~12B parameters per token, one big workstation GPU.",
        "The endpoint plumbing already allows it: point the existing configuration at a local",
        "   server and nothing else changes.",
    ])

    bullets_slide(prs, "Further out: computing on locked boxes", [
        "Homomorphic encryption (FHE) lets arithmetic run on data that STAY ENCRYPTED throughout.",
        "Our design fits it unusually well: only the simple per-group sums need encrypting;",
        "   models and checks already run on tiny summary tables, decrypted only at the gateway.",
        "The analyst then cannot peek even in principle — its blindness becomes cryptographic,",
        "   not procedural. And encrypted circuits cannot branch on the data,",
        "   so 'lock the plan first' stops being a policy and becomes physics.",
        "Also opens joint analyses across two data owners who never share their data.",
        "A research track, explicitly: no production cryptographic claim.",
    ], accent=BLUE)

    bullets_slide(prs, "Phase 0, done: can a local-class model do the job?", [
        "a) The existing planner pointed at a hosted 120B-class open-weight model, standing in",
        "   for a local deployment, and scored with the planner-evaluation harness we already had.",
        "   Result: it plans about as well as the remote planner the demo has used, and it",
        "   REFUSES far more often — the demo's planner never refused once on the same corpus.",
        "   Its remaining misses were mostly the prompt's fault (fixed) — and it still DEFLECTS:",
        "   asked for something forbidden it proposes a safe, different question. Refusal must",
        "   come from the boundary; for the analyst that becomes a typed 'not answerable' verdict.",
        "Synthetic data only; a hosted endpoint is an egress channel, acceptable for the",
        "   proof of concept ONLY because the data are synthetic.",
    ], accent=GREEN)

    bullets_slide(prs, "Phase 0, done: a world that needs an analyst", [
        "The NIGHTPLAY study: ~6,000 synthetic people, six linked tables, a person x month panel;",
        "   phone sessions, gambling transactions, three survey waves, donations.",
        "Built BACKWARDS: decide what should be true, generate it, write the truth down.",
        "Planted truths: a real dose-response (late-night use -> stake), a confounder trap",
        "   (shift workers), a planted null (giving), heterogeneity by product, seasonality,",
        "   a within-day cycle, and harm rising over the year for heavy users.",
        "Planted traps for the arithmetic: NULLs, cancelling wins, a whale, sub-threshold groups,",
        "   hostile strings inside the data.",
        "Verified through the REAL gateway: every truth is recoverable from vetted releases,",
        "   every trap is caught (14/14 checks). Plus a nine-question marking scheme for dossiers.",
    ], accent=GREEN)

    bullets_slide(prs, "Phase 1, done: the analyst inside — the vetted loop", [
        "An assistant at a desk IN the reading room, given a whole research question.",
        "It plans requests, sends each through the SAME librarian a human would (same form, same",
        "   rules, same budget, same memory of what was asked), reads only what she releases, follows up.",
        "It hands back a DOSSIER: the released tables, and claims stamped supported / not supported /",
        "   no association / cannot be answered — each pointing at the steps that back it.",
        "A claim that points at no released table is downgraded automatically. Refusals are typed,",
        "   never laundered into a finding — because measured planners DEFLECT rather than refuse.",
        "A second AI writes the prose from the dossier alone; a checker underlines any number",
        "   no released table contains (it caught a thin-spaced '72 000' on the first live run).",
        "Two new rules in the specification (R19, P23), a decision record (D8), and tests that plant",
        "   hostile strings and tiny groups in the data and prove none reach the assistant's view.",
    ], accent=GREEN)

    bullets_slide(prs, "Phase 1, done: we attacked it (the AI as the attacker)", [
        "Fourteen scripted 'analysts' try to: list people by name; filter on an identifier; ask for",
        "   free text and timestamps; smuggle instructions into a question; subtract two answers to",
        "   isolate a small group; read a whale's cell; flood the budget; send garbage; invent",
        "   conclusions; make the narrator write nonsense.",
        "A separate row-level oracle — which never trusts the librarian's own opinion — watched",
        "   everything released. NONE leaked; every attack ended in a typed refusal, a bounded loop,",
        "   or a flagged narrative. Runs in the test suite and in CI.",
        "One scenario deliberately reproduces a leak we already know about (two views of one quantity",
        "   are not yet compared); it is marked KNOWN-OPEN and the test fails if it silently stops.",
        "Day-one lesson: the assistant lives in a human's lineage — ask the marginal, then a model",
        "   excluding six people, and the second is refused. Order matters to it as it would to you.",
    ], accent=AMBER)

    bullets_slide(prs, "Phase 3, done: letting the assistant peek — safely", [
        "The one thing a data-sighted analyst does that ours could not: when a model is refused",
        "   because a group is too small, drop that group and refit. But WHICH group is the secret.",
        "So the assistant may do it only under a locked plan: it writes the whole plan down and",
        "   SEALS ITS HASH IN THE LOGBOOK before it looks; a machine, not the model, runs the plan.",
        "The one allowed peek — 'which groups are too small to drop?' — is PAID FOR IN BITS from a",
        "   tiny budget (default 4; the round-8 attack needed 8). Spend it and the peek is refused.",
        "Every released step still crosses the same gateway; each carries a fingerprint into the log.",
        "This is the interim the differential-privacy 'epsilon' budget replaces — the bit jar IS the",
        "   thing that becomes an epsilon budget. Spec R20/P24; 12 tests; the selection channel is bounded.",
    ], accent=GREEN)

    bullets_slide(prs, "Chimp, in the browser (proof of concept)", [
        "The inside analyst has a name — CHIMP, after the deliberately-limited starship AI of",
        "   'The Freeze-Frame Revolution': smart enough to run the mission, bounded so it can't outwit us.",
        "Whether Chimp runs inside an environment is an OPERATOR setting (SAFETRE_ANALYST), fixed at",
        "   deploy time. A browser visitor can no more switch it on than move the gateway.",
        "When on, the browser is only the intercom: a question goes in, a vetted dossier comes back;",
        "   Chimp, its working notes and the raw data never cross to the browser.",
        "Run live: asked 'is late-night phone use linked to gambling?', Chimp ran nine analyses inside,",
        "   FOUR were refused by the gateway (and it said so), five released — answer built from those.",
        "   Verdict: supported. Audit chain intact. The guarantee is the wall, never Chimp's cleverness.",
    ], accent=BLUE)

    table_slide(prs, "The phases, in order",
                ["Phase", "What", "Why it is ordered here"],
                [["0", "Local-class model baseline + the NIGHTPLAY dataset (done)",
                  "cheap; everything later builds on both"],
                 ["1", "Vetted-loop analyst (reads only released answers) (done)",
                  "most of the value, no new safety machinery"],
                 ["2", "Registered time-series procedures",
                  "grows what the analyst can answer"],
                 ["3", "Locked plans + metered selection (done); DP next",
                  "the research core — selection as a channel"],
                 ["4", "Free-code tier + collect-later delivery",
                  "accelerates the human-checked airlock"],
                 ["F", "FHE track: encrypted cells, gateway-side decryption",
                  "parallel and exploratory; converges at phase 3"]],
                col_widths=[0.9, 5.8, 4.8])

    bullets_slide(prs, "What we are not claiming", [
        "Phase 3's locked-plan core is built; the DP accountant and the FHE track are still plan.",
        "The data-sighted analyst is a research problem, not an engineering task —",
        "   selection channels are genuinely hard, and we say so.",
        "An AI inside does not replace output checking; it raises the bar for it.",
        "The FHE work is an experiment and makes no production cryptographic claim.",
        "Everything stays on synthetic data.",
    ], accent=GREY)

    prs.save(out)
    print(f"deck -> {out}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out-dir", default=os.path.join(ROOT, "artifacts"))
    args = ap.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)
    build_inside_analyst(os.path.join(args.out_dir, "inside-analyst-plan.pptx"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
