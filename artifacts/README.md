# Presentation artifacts

The full slide decks and the rendered user guide live here on disk but are
**not tracked in git** (each deck revision added ~450 KB of undiffable binary
to the history); distribute them as GitHub Release assets instead. Three small
plain-language explainers are the deliberate exceptions and ARE committed:
`ELIF.ppt`, `ELIF-FORMAL.ppt` and `GUIDELINES.ppt`.

## The overview deck is generated

`safe-tre-agent-overview.pptx` is built by `scripts/make_decks.py` from the
current project state and live screenshots — the generator is the source of
truth, the `.pptx` is a disposable output:

```bash
scripts/restart_web.sh                                   # serve the app
uv run --group decks python scripts/make_decks.py        # capture + build
```

Screenshots land in `artifacts/shots/` (also gitignored); pass `--no-capture`
to rebuild from existing ones. Regenerate after any UI or status change so the
deck never drifts from the interface.

## The component map is generated

`safe-tre-agent-components.pptx` — the component & trust map (runtime
pipeline, assurance toolchain, upstream-project provenance) — is built by
`scripts/make_component_map.py`. No screenshots, so no capture step; the
red-team corpus size is read from `redteam/attacks.yaml` at build time:

```bash
uv run --group decks python scripts/make_component_map.py
```

Regenerate after adding a procedure, a formal model, a CI job, or a runtime
dependency, so the map never drifts from the code.

## Still hand-made

- `userguide.pdf` — rendered from `docs/userguide.md`
- `safe-tre-agent-technical.pptx`, `safe-tre-agent-best-practice.pptx` —
  maintained alongside `docs/writeup.md` and `docs/best-practice-review.md`;
  their screenshots are outdated (dark console UI) until folded into the
  generator.
