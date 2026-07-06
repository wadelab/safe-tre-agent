# Presentation artifacts

The slide decks and the rendered user guide live here on disk but are **not
tracked in git**: each deck revision added ~450 KB of undiffable binary to the
history. Distribute them as GitHub Release assets instead, and treat the
markdown sources as canonical:

- `userguide.pdf` — rendered from `docs/userguide.md`
- `safe-tre-agent-overview.pptx`, `safe-tre-agent-technical.pptx`,
  `safe-tre-agent-best-practice.pptx` — maintained alongside the docs they
  summarise (`docs/writeup.md`, `docs/security.md`,
  `docs/best-practice-review.md`)

Earlier revisions remain in git history before the untracking commit.
