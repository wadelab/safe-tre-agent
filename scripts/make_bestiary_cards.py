"""Build the committed bestiary card images from the print masters.

The card art is exported print-ready: 24 PNGs, 2400 px short edge, 300 DPI,
about 7 MB each — 158 MB for the set. That is the right thing to keep and the
wrong thing to commit, to a repository whose entire tracked content is a few
megabytes and whose history was deliberately slimmed once already. So the
masters stay local (gitignored) and this writes the web derivatives that ship.

Three reductions, in order, each with a stated reason:

1. **Resize.** `docs/bestiary.md` displays each card at a specific width — 180
   for the family gallery up to 420 for the sleeping dials. The derivative is
   twice that (crisp on a 2x display), with a floor of 600 px so the same files
   are still respectable when `make_bestiary_deck.py` puts them on a slide at
   about four inches. Sizing from the page means the bytes stay proportional to
   what a reader actually sees; the floor means the deck does not need a second
   set.
2. **Quantise.** 256-colour palette with Floyd-Steinberg dithering. Measured
   against the *resized* image, not the master — the resize is deliberate and
   the quantisation is the part that has to be invisible. Any card whose error
   exceeds 3/255 is kept at full colour instead; in practice the worst is
   under 2.
3. **Re-encode.** `optimize=True, compress_level=9`.

Net: 158 MB of masters become about 6.5 MB of committed PNGs.

Run after changing the card art:

    uv run --group decks python scripts/make_bestiary_cards.py
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import sys

import numpy as np
from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MASTERS = os.path.join(ROOT, "docs", "bestiaryImaging")
OUT = os.path.join(ROOT, "docs", "figures", "bestiary")
PAGE = os.path.join(ROOT, "docs", "bestiary.md")

# A card is never written smaller than this, so the same files serve the deck.
MIN_WIDTH = 600
# Displayed at 1x; the derivative is twice this. Used when a card is not (yet)
# referenced by the page.
DEFAULT_DISPLAY = 300
# Above this mean absolute error, keep full colour rather than quantise.
MAX_QUANTISATION_ERROR = 3.0

Image.MAX_IMAGE_PIXELS = None            # the masters are legitimately huge


def display_widths() -> dict[str, int]:
    """The width each card is shown at, read from the page itself.

    Read rather than configured, so the two cannot drift: change the layout and
    the next run resizes to match.
    """
    if not os.path.exists(PAGE):
        return {}
    return {m.group(1): int(m.group(2)) for m in re.finditer(
        r'figures/bestiary/(\S+?\.png)\)\{ width="(\d+)"', open(PAGE).read())}


def masters() -> list[str]:
    return sorted(glob.glob(os.path.join(MASTERS, "**", "*.png"), recursive=True))


def build(dry_run: bool = False) -> int:
    found = masters()
    if not found:
        print(f"no card masters under {os.path.relpath(MASTERS, ROOT)}/ — they are "
              f"gitignored, so a fresh checkout has the committed derivatives "
              f"and nothing to rebuild from.", file=sys.stderr)
        return 1

    shown = display_widths()
    os.makedirs(OUT, exist_ok=True)
    before = after = 0
    worst = ("", 0.0)
    for path in found:
        name = os.path.basename(path)
        before += os.path.getsize(path)
        target = max(shown.get(name, DEFAULT_DISPLAY) * 2, MIN_WIDTH)

        image = Image.open(path).convert("RGB")
        if image.width > target:
            height = round(image.height * target / image.width)
            image = image.resize((target, height), Image.LANCZOS)

        quantised = image.quantize(colors=256, method=Image.MEDIANCUT,
                                   dither=Image.FLOYDSTEINBERG)
        error = float(np.abs(np.asarray(image, dtype=float)
                             - np.asarray(quantised.convert("RGB"), dtype=float)).mean())
        if error > worst[1]:
            worst = (name, error)

        destination = os.path.join(OUT, name)
        if not dry_run:
            chosen = quantised if error <= MAX_QUANTISATION_ERROR else image
            chosen.save(destination, optimize=True, compress_level=9)
        after += os.path.getsize(destination) if os.path.exists(destination) else 0

    print(f"{len(found)} cards")
    print(f"  masters     : {before / 1e6:6.1f} MB  (gitignored)")
    print(f"  committed   : {after / 1e6:6.1f} MB  -> {os.path.relpath(OUT, ROOT)}/")
    print(f"  worst quantisation error: {worst[1]:.2f} / 255  ({worst[0]})")
    if shown:
        print(f"  sized from the page: {sorted(set(shown.values()))} px displayed, "
              f"2x with a {MIN_WIDTH} px floor")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true",
                        help="report what would be written, write nothing")
    return build(dry_run=parser.parse_args().dry_run)


if __name__ == "__main__":
    sys.exit(main())
