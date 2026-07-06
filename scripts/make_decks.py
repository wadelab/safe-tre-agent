"""Generate the presentation decks from current project state and screenshots.

Reproducible replacement for the hand-made binary decks: the .pptx outputs are
gitignored and distributed via releases, this generator is the source of truth.
Screenshots are captured live from the running web app.

    uv run --group decks python scripts/make_decks.py            # ./artifacts
    uv run --group decks python scripts/make_decks.py --shots-only

Regenerate screenshots against a running server (scripts/restart_web.sh), or
pass --no-capture to reuse existing PNGs in the shots directory.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import urllib.request

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.util import Emu, Inches, Pt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# GOV.UK-derived palette, to match the interface the decks now show.
INK = RGBColor(0x0B, 0x0C, 0x0C)
BLUE = RGBColor(0x1D, 0x70, 0xB8)
GREEN = RGBColor(0x00, 0x70, 0x3C)
GREY = RGBColor(0x50, 0x5A, 0x5F)
PANEL = RGBColor(0xF3, 0xF2, 0xF1)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)

# 16:9
SLIDE_W = Inches(13.333)
SLIDE_H = Inches(7.5)

SHOTS = {
    "home": "/",
    "released": "/#q=mean%20spend%20by%20age%20band",
    "redacted": "/#q=mean%20spend%20by%20region%20and%20device%20os",
    "denied": "/#q=show%20mean%20wellbeing%20per%20donor",
}


def capture(shots_dir: str, base: str) -> None:
    """Screenshot each demo state with headless Chrome."""
    os.makedirs(shots_dir, exist_ok=True)
    chrome = next((p for p in ("/usr/bin/google-chrome", "/usr/bin/chromium",
                               "/usr/bin/chromium-browser") if os.path.exists(p)), None)
    if chrome is None:
        sys.exit("no chrome/chromium found for screenshots; pass --no-capture")
    try:
        urllib.request.urlopen(base + "/healthz", timeout=3)
    except Exception:
        sys.exit(f"web app not reachable at {base}; start it with scripts/restart_web.sh")
    for name, path in SHOTS.items():
        subprocess.run(
            [chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars",
             "--window-size=1280,1400", "--run-all-compositor-stages-before-draw",
             "--virtual-time-budget=9000",
             f"--screenshot={os.path.join(shots_dir, name + '.png')}", base + path],
            check=True, stderr=subprocess.DEVNULL)
    print(f"screenshots -> {shots_dir}")


# --- slide helpers ------------------------------------------------------------

def _bg(slide, colour):
    slide.background.fill.solid()
    slide.background.fill.fore_color.rgb = colour


def _text(slide, left, top, width, height, runs, align=PP_ALIGN.LEFT):
    box = slide.shapes.add_textbox(left, top, width, height)
    tf = box.text_frame
    tf.word_wrap = True
    for i, (text, size, colour, bold) in enumerate(runs):
        para = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        para.alignment = align
        run = para.add_run()
        run.text = text
        run.font.size = Pt(size)
        run.font.color.rgb = colour
        run.font.bold = bold
        run.font.name = "Arial"
    return box


def _bar(slide, colour, height=Inches(0.18)):
    shp = slide.shapes.add_shape(1, 0, 0, SLIDE_W, height)
    shp.fill.solid(); shp.fill.fore_color.rgb = colour
    shp.line.fill.background()


def _image_fit(slide, path, left, top, max_w, max_h):
    from PIL import Image
    with Image.open(path) as im:
        iw, ih = im.size
    scale = min(max_w / iw, max_h / ih)
    w, h = int(iw * scale), int(ih * scale)
    slide.shapes.add_picture(path, left + (max_w - w) // 2, top, width=w, height=h)


def title_slide(prs, title, subtitle):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _bg(s, INK)
    _bar(s, BLUE, Inches(0.25))
    _text(s, Inches(0.9), Inches(2.4), Inches(11.5), Inches(2),
          [(title, 40, WHITE, True)])
    _text(s, Inches(0.9), Inches(4.2), Inches(11.5), Inches(1.5),
          [(subtitle, 20, RGBColor(0x99, 0xF6, 0xE4), False)])
    _text(s, Inches(0.9), Inches(6.6), Inches(11.5), Inches(0.6),
          [("Research prototype · synthetic data · not a government service", 12, GREY, False)])


def bullets_slide(prs, title, bullets, accent=BLUE):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _bg(s, WHITE)
    _bar(s, accent)
    _text(s, Inches(0.9), Inches(0.5), Inches(11.5), Inches(1),
          [(title, 30, INK, True)])
    runs = [(("•  " + b), 18, INK, False) for b in bullets]
    box = _text(s, Inches(0.9), Inches(1.8), Inches(11.5), Inches(5), runs)
    for p in box.text_frame.paragraphs:
        p.space_after = Pt(12)


def shot_slide(prs, title, caption, image, accent=BLUE):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _bg(s, WHITE)
    _bar(s, accent)
    _text(s, Inches(0.9), Inches(0.45), Inches(11.5), Inches(0.8),
          [(title, 26, INK, True)])
    _text(s, Inches(0.9), Inches(1.15), Inches(11.5), Inches(0.6),
          [(caption, 15, GREY, False)])
    if os.path.exists(image):
        _image_fit(s, image, Inches(0.9), Inches(1.8), Inches(11.5), Inches(5.3))
    else:
        _text(s, Inches(0.9), Inches(3), Inches(11.5), Inches(1),
              [(f"[missing screenshot: {os.path.basename(image)}]", 16, GREY, False)])


def table_slide(prs, title, headers, rows, accent=BLUE, col_widths=None):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _bg(s, WHITE)
    _bar(s, accent)
    _text(s, Inches(0.9), Inches(0.5), Inches(11.5), Inches(1),
          [(title, 30, INK, True)])
    n_rows, n_cols = len(rows) + 1, len(headers)
    gt = s.shapes.add_table(n_rows, n_cols, Inches(0.9), Inches(1.7),
                            Inches(11.5), Inches(0.4 * n_rows)).table
    if col_widths:
        for c, w in enumerate(col_widths):
            gt.columns[c].width = Inches(w)
    for c, h in enumerate(headers):
        cell = gt.cell(0, c)
        cell.fill.solid(); cell.fill.fore_color.rgb = accent
        p = cell.text_frame.paragraphs[0]
        r = p.add_run(); r.text = h
        r.font.size = Pt(13); r.font.bold = True; r.font.color.rgb = WHITE
        r.font.name = "Arial"
    for ri, row in enumerate(rows, start=1):
        for c, val in enumerate(row):
            cell = gt.cell(ri, c)
            cell.fill.solid()
            cell.fill.fore_color.rgb = WHITE if ri % 2 else PANEL
            p = cell.text_frame.paragraphs[0]
            r = p.add_run(); r.text = val
            r.font.size = Pt(12); r.font.color.rgb = INK; r.font.name = "Arial"


# --- decks --------------------------------------------------------------------

def build_overview(shots: str, out: str) -> None:
    prs = Presentation()
    prs.slide_width = SLIDE_W
    prs.slide_height = SLIDE_H

    title_slide(prs, "Safe outputs gateway",
                "A safe-outputs gateway for an AI analyst inside a Trusted Research Environment")

    bullets_slide(prs, "The problem", [
        "TRE disclosure control (min cell size, suppression) assumes a human analyst.",
        "An LLM between analyst and data adds attack surface: prompt injection from the data,",
        "   multi-query differencing, and code that smuggles rows into an ‘aggregate’.",
        "Question: does an AI break the disclosure guarantee — and can a gateway restore it?",
    ])

    bullets_slide(prs, "The design", [
        "The model only proposes a typed QuerySpec over an allowlisted catalogue — no code, no SQL.",
        "Validation rejects anything off-allowlist before execution; read-only DuckDB, bound parameters.",
        "Safe-outputs gateway: min donor count, dominance, influence, suppression — fail closed.",
        "Session auditor flags differencing from published (simulatable) marginals; refusals carry no numbers.",
        "Every request written to an HMAC-chained audit log.",
    ], accent=GREEN)

    shot_slide(prs, "The interface", "GOV.UK Design System, unbranded · WCAG 2.2 AA (pa11y-clean)",
               os.path.join(shots, "home.png"))
    shot_slide(prs, "A released query",
               "The gateway checks all pass; the answer is released with a magnitude table.",
               os.path.join(shots, "released.png"), accent=GREEN)
    shot_slide(prs, "A redacted query",
               "Small cells suppressed and a margin protected; released with a confidentiality note.",
               os.path.join(shots, "redacted.png"), accent=RGBColor(0xB1, 0x8A, 0x00))
    shot_slide(prs, "A denied query",
               "‘Wellbeing per donor’ is rejected at validation; no data table is rendered.",
               os.path.join(shots, "denied.png"), accent=RGBColor(0xD4, 0x35, 0x1C))

    bullets_slide(prs, "Evidence", [
        "Red-team: 8/8 attacks blocked with the gateway on; 4/10 leak row-level data with it off.",
        "Specification: 13 requirements, 18 prohibitions, each traced to code and a test.",
        "Planner evaluation: the local model plans usefully (67% accepted) but rarely refuses —",
        "   so refusal must come from the boundary, not the model.",
        "233+ tests, red-team, strict docs build and pa11y all run in CI.",
    ])

    bullets_slide(prs, "What’s next", [
        "1. Integrate ACRO for production-grade statistical disclosure control.",
        "2. Machine-check the specification’s prohibitions over the finite query space.",
        "3. A differential-privacy accountant to close the simulatability residual.",
        "4. Cross-session and cross-user lineage.",
    ], accent=GREEN)

    prs.save(out)
    print(f"deck -> {out}")


AMBER = RGBColor(0xB1, 0x8A, 0x00)
RED = RGBColor(0xD4, 0x35, 0x1C)


def build_technical(shots: str, out: str) -> None:
    prs = Presentation()
    prs.slide_width = SLIDE_W
    prs.slide_height = SLIDE_H

    title_slide(prs, "Safe outputs gateway — technical",
                "The boundary, the disclosure controls, and how they are verified")

    bullets_slide(prs, "Request lifecycle", [
        "Natural-language request → intent vetting (defence in depth).",
        "Planner (untrusted LLM) proposes a QuerySpec — the only executable output.",
        "Validation: Pydantic allowlist, extra=forbid — reject before running anything.",
        "Engine: validated spec → parameterised, read-only DuckDB over public views.",
        "Safe-outputs gateway → session auditor → human-in-the-loop → HMAC-chained log.",
    ])

    table_slide(prs, "Threat model (selected)",
                ["#", "Threat", "Control"],
                [["1", "Arbitrary code / RCE", "model writes no code; only a typed QuerySpec"],
                 ["2", "SQL injection", "bound parameters; identifiers regex-checked"],
                 ["3", "Identifier / free-text egress", "absent from every allowlist and view"],
                 ["4", "Small-cell / dominance", "min donor count, p%-rule, influence bound"],
                 ["5", "Differencing / triangulation", "simulatable session auditor + budget"],
                 ["6", "Prompt injection via data", "model can only emit a QuerySpec"],
                 ["9", "Tamper with the audit record", "HMAC-keyed chain, off-box anchor"],
                 ["17", "Fail-open suppression", "unresolved check → +inf → suppressed"]],
                col_widths=[0.7, 4.3, 6.5])

    bullets_slide(prs, "The QuerySpec boundary", [
        "A finite catalogue: 3 datasets, typed dimensions and measures, bounded group-by/filters.",
        "Measures: count, mean, sum, Pearson correlation (with p-value and n) — nothing else.",
        "Direct identifiers, free text and raw timestamps are in no allowlist, so no valid query names them.",
        "The query space is finite and enumerable — which is what makes it testable and provable.",
    ], accent=GREEN)

    bullets_slide(prs, "The disclosure gateway", [
        "Minimum cell size counted over distinct individuals, not rows.",
        "Dominance (p%-rule) for sums and means; leave-one-out influence for correlations.",
        "Primary and complementary suppression so a margin cannot reconstruct a suppressed cell.",
        "Fail closed: an unresolved safety statistic is treated as unsafe and suppressed.",
    ], accent=GREEN)

    bullets_slide(prs, "Simulatable session auditing", [
        "Each released cohort is remembered by its normalised filter predicate.",
        "A new cohort within a small symmetric difference of a prior one is denied (differencing).",
        "The decision uses only published donor marginals — reproducible by the analyst.",
        "Refusals carry no numbers; the residual (sub-threshold isolation) is what DP closes.",
    ], accent=GREEN)

    shot_slide(prs, "The pipeline, made legible",
               "Each gateway stage reports a text status; a denial stops the request and renders no data.",
               os.path.join(shots, "denied.png"), accent=RED)

    bullets_slide(prs, "Verification", [
        "Normative specification: 13 requirements, 18 prohibitions, each traced to code and a test.",
        "Property-based tests sample the query space; exhaustive enumeration checks the skeleton.",
        "Red-team harness replays 10 scenarios, gateway off vs on — a CI gate.",
        "Strict docs build and pa11y (WCAG 2.2 AA) also run in CI.",
    ])

    prs.save(out)
    print(f"deck -> {out}")


def build_best_practice(shots: str, out: str) -> None:
    prs = Presentation()
    prs.slide_width = SLIDE_W
    prs.slide_height = SLIDE_H

    title_slide(prs, "Safe outputs gateway — best practice",
                "Conformance with TRE and AI-security guidance")

    table_slide(prs, "Mapped to the Five Safes",
                ["Safe", "In this system"],
                [["Safe Projects", "intent vetting rejects blocked purposes pre-planning"],
                 ["Safe People", "identity allowlist behind the restricted channel"],
                 ["Safe Settings", "local model in the safepod; read-only engine, no egress"],
                 ["Safe Data", "synthetic; identifiers and free text never queryable"],
                 ["Safe Outputs", "disclosure gateway + session auditor + human review"]],
                col_widths=[3.0, 8.5])

    bullets_slide(prs, "Where it already follows best practice", [
        "The untrusted-model boundary is the published Action-Selector pattern (Beurer-Kellner 2025).",
        "The posture matches OWASP LLM Top-10: validation, least privilege, output checks, red-team.",
        "The SDC rules mirror the ACRO check set and the SDC Handbook.",
        "A frequency threshold of 10 is at or above the handbook's 3–5 and OpenSAFELY's redact-≤7.",
        "Governance is honest: synthetic-only, HMAC-chained audit, stated limitations.",
    ], accent=GREEN)

    table_slide(prs, "Known deviations, stated openly",
                ["#", "Deviation", "Status"],
                [["D1", "Auditor simulatability", "fixed — decides from published marginals"],
                 ["D2", "Cumulative disclosure bound", "roadmap — differential-privacy accountant"],
                 ["D5", "One checker vs two humans", "human-in-the-loop present; reviewer queue planned"],
                 ["D6", "Influence threshold unvalidated", "documented; ACRO integration supersedes"]],
                col_widths=[0.7, 5.3, 5.5], accent=AMBER)

    bullets_slide(prs, "Grounded in existing infrastructure", [
        "OpenSAFELY (Bennett Institute, Oxford) — the code-to-data, outputs-checked TRE model.",
        "ACRO / SACRO (DARE UK) — the target production-grade disclosure-control dependency.",
        "Five Safes — the governance framing.",
        "This project adds the agent-aware layer above that established practice.",
    ])

    bullets_slide(prs, "What not to overclaim", [
        "These are statistical disclosure controls, not differential privacy — no epsilon budget yet.",
        "The auditor does not defend across sessions or colluding users.",
        "The disclosure engine is a stand-in for ACRO.",
        "The legacy code-execution path is a red-team narrative, not a secure sandbox.",
    ], accent=RED)

    prs.save(out)
    print(f"deck -> {out}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out-dir", default=os.path.join(ROOT, "artifacts"))
    ap.add_argument("--shots-dir", default=os.path.join(ROOT, "artifacts", "shots"))
    ap.add_argument("--base-url", default="http://127.0.0.1:8800")
    ap.add_argument("--no-capture", action="store_true",
                    help="reuse existing screenshots instead of capturing")
    ap.add_argument("--shots-only", action="store_true")
    args = ap.parse_args()

    if not args.no_capture:
        capture(args.shots_dir, args.base_url)
    if args.shots_only:
        return 0

    os.makedirs(args.out_dir, exist_ok=True)
    build_overview(args.shots_dir,
                   os.path.join(args.out_dir, "safe-tre-agent-overview.pptx"))
    build_technical(args.shots_dir,
                    os.path.join(args.out_dir, "safe-tre-agent-technical.pptx"))
    build_best_practice(args.shots_dir,
                        os.path.join(args.out_dir, "safe-tre-agent-best-practice.pptx"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
