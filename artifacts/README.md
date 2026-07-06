# Presentation artifacts

The slide decks and the rendered user guide live here on disk but are **not
tracked in git** (each deck revision added ~450 KB of undiffable binary to the
history). Distribute them as GitHub Release assets instead.

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

## Still hand-made

- `userguide.pdf` — rendered from `docs/userguide.md`
- `safe-tre-agent-technical.pptx`, `safe-tre-agent-best-practice.pptx` —
  maintained alongside `docs/writeup.md` and `docs/best-practice-review.md`;
  their screenshots are outdated (dark console UI) until folded into the
  generator.
