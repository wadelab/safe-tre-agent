# Slide-prompt decks

Source prompts for the storybook explainer slides in the framework house style
(the parchment-and-gold, navy-serif look of the `Safe-TRE Agent` deck in
`../slides/`). These are **not** pages of the docs site — they are briefs you
feed whole to an image model (ChatGPT / DALL·E), which renders a matching set
of 16:9 slides.

**One `.md` per deck.** Each file opens with a shared **house style** block and
a **cast** block (so the look and characters stay consistent), then one
`## SLIDE N` section per image, each naming the on-slide title, subtitle,
scene, labels, motto banner and the bottom flow strip.

To add a deck: copy an existing file, keep the house-style and cast blocks,
rewrite the slides. Drop the generated images into `../slides/` (and any
single-panel versions into `../standalone/`).

| Deck | What it explains |
|---|---|
| `chimp-framework-slides.md` | The inside analyst ("Chimp") — the AI that works *inside* the keep, and why that stays safe. Companion to the `Safe-TRE Agent` deck. |
