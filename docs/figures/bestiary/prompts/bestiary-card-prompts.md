# Bestiary card art — the house style and template

The prompt convention for the **Security Bestiary** cards (the collectible
"caged beast" cards in `docs/figures/bestiary/`). One creature per card; the
creature is a mnemonic for one attack class, and the card's fields carry the
real security concept. Feed the *House style* block plus one *Card* block to
the image model; generate **art only** where you can, then set the text in SVG
so it stays exact (see *Production* below).

The lore each creature indexes lives in `docs/bestiary.md` — the families,
the grammar, and each specimen's cage and keeper. That is the source of WHAT
to depict; this file is HOW.

---

## HOUSE STYLE (applies to every card)

**Overall look:** a nostalgic late-1990s collectible monster card aesthetic —
early trading-card conventions, without copying any specific franchise assets,
logos, characters, fonts, symbols, card backs, or exact layouts. Slightly
handmade, printed and imperfect rather than glossy-modern.

**Card structure:** vertical card; warm yellow/cream textured border; a thin
inner rule; a large rectangular illustration window in the upper half; a
compact species/type line directly beneath the art; then two or three "move"
rows with circular energy-like icons, large attack names, short effect text,
and numeric values aligned right; a narrow stats row; and an italic
flavour-text box near the bottom. Add tiny faux set-number and
illustrator-credit details for authenticity — original names and marks only.

**Typography:** bold black title at upper left; compact sans/serif metadata
around it; a dark red or brown numeric stat at upper right. Slightly
condensed, utilitarian late-90s print type rather than modern display fonts.
Keep wording simple enough to typeset separately in SVG.

**Illustration:** whimsical hand-painted fantasy creature art; cel-like
outlines with soft watercolour/gouache shading; bright but somewhat muted
natural colours; lush scenic backgrounds; expressive eyes; **friendly menace,
not horror**. Should read as traditional card illustration scanned from
painted artwork — not a 3D render or polished digital concept art.

**Surface/print treatment:** lightly aged paper, subtle halftone/grain,
off-white ink areas, imperfect print registration, faint edge wear, modest
contrast. Avoid metallic gradients, neon UI, elaborate gemstones, embossed
borders, or modern esports aesthetics.

**Security cards specifically:** keep the creature identity and metaphor, and
convert the security concept into **moves**, a passive trait, weakness /
resistance / retreat cost, and short flavour. (E.g. The Subtractor uses
attacks named **Nibble** and **Difference Jolt**; its art shows a small
mischievous creature comparing near-identical baskets.)

## HOLO / "SPECIAL PHASE" VARIANT (anticipated specimens)

A card is **holo-foil** when it is *Uncaged* — an anticipated threat with **no
hardening-log number yet, keeper not on duty**. The foil is the tell that the
pen is a hope, not yet a control. Holo cards carry:

- an iridescent prismatic foil sheen over frame and art window (a display-case
  chase-card finish), rainbow refractions, fine starburst grain;
- a `HOLO SPECIAL` banner and a faux set number `NN/??` with a foil star;
- the passive trait **Uncaged — this specimen is anticipated: no finding
  number, keeper not on duty**;
- a footer line such as *Security Bestiary Special Phase · internal research
  creature*.

When a holo threat earns a real hardening number, it loses the foil and joins
the ordinary (non-holo) bestiary.

## CARD TEMPLATE (fill one per creature)

- **Name** (upper-left title) and a faux number (upper-right).
- **Species / type line** — the class in the fiction, plus the domain
  (e.g. `Selection Daemon (internal AI)`).
- **Passive trait** — one line (for holo cards, the *Uncaged* trait above).
- **Move 1 / Move 2** — an evocative attack name, a one-line effect written in
  the fiction, and a numeric value (or `10×` etc.) at the right.
- **Weakness · Resistance · Retreat** — name the CONTROL that cages it as the
  weakness (e.g. `Weakness: Locked Plan`); resistance/retreat optional.
- **Flavour** — one italic sentence that states the threat obliquely.
- **Illus. credit + set number** in the footer.

Keep the metaphor at the class level and the truth at the specimen level: the
moves and weakness should map to a real attack and a real control, never
invent a new threat model.

---

## ART PROMPT SKELETON (per card)

> `<one or two sentences of scene: the creature, what it is doing, its
> setting — drawn from the specimen's metaphor in docs/bestiary.md>.`
>
> **Style suffix (append):** *Whimsical hand-painted fantasy creature art,
> cel-like outlines with soft watercolour and gouache shading, bright but
> muted natural colours, lush scenic background, expressive eyes, friendly
> menace rather than horror; looks like traditional card illustration scanned
> from painted artwork, late-1990s collectible-card aesthetic; illustration
> only — no text, no frame, no card border.* *(For holo cards, add: legendary
> holographic chase-card finish — iridescent prismatic foil sweeping
> diagonally, rainbow refractions, fine starburst sparkle grain.)*

## PRODUCTION WORKFLOW

Generate **art only** where possible, then compose the card in SVG so the text
stays exact and editable:

1. raster illustration layer (the art-only generation),
2. vector frame and energy icons,
3. editable title / stats layer,
4. editable attack / body-text layer,
5. optional print-texture overlay.

Committed cards are the derivatives, not the print masters: masters stay in
`docs/bestiaryImaging/` (gitignored); the web copies live in
`docs/figures/bestiary/` — palette-256 PNG for the painted cards
(`scripts/make_bestiary_cards.py`), and **webp** for the holo cards (their
foil gradients band under a 256-colour palette).

---

*This is the first written record of the bestiary house style — it was a chat
prompt until now. The worked examples are cards 25–30 (the Uncaged set): each
took the skeleton above and named its move-pair, weakness (the control) and
flavour from the threat it indexes.*
