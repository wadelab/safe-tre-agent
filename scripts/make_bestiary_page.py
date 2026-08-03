"""Build the self-contained bestiary artifact from its editable source.

The words live in `docs/bestiary_artifact/page.html` (plain text between the
tags); the design is in `theme.css`, the fonts in `garamond.css`, and the card
art in `docs/figures/bestiary/`. This script inlines all of it into one
self-contained page — every image a `data:` URI, no external requests — ready
to publish as an Artifact.

    uv run python scripts/make_bestiary_page.py

Edit the source, re-run this, then republish `artifacts/bestiary_page.html`.
The decorative hero "spines" strip is regenerated here as small thumbnails, so
the source stays free of image data and the built page stays small.
"""

from __future__ import annotations

import argparse
import base64
import io
import os
import re
import sys

from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "docs", "bestiary_artifact")
CARDS = os.path.join(ROOT, "docs", "figures", "bestiary")
OUT = os.path.join(ROOT, "artifacts", "bestiary_page.html")
S = re.DOTALL
PATH = re.compile(r'\.\./figures/bestiary/([^"]+)\.webp')


def _read(name: str) -> str:
    with open(os.path.join(SRC, name), encoding="utf-8") as fh:
        return fh.read()


def _full(stem: str) -> str:
    with open(os.path.join(CARDS, stem + ".webp"), "rb") as fh:
        return "data:image/webp;base64," + base64.b64encode(fh.read()).decode()


def _thumb(stem: str, width: int = 150) -> str:
    with Image.open(os.path.join(CARDS, stem + ".webp")) as im:
        im = im.convert("RGB")
        h = round(im.height * width / im.width)
        buf = io.BytesIO()
        im.resize((width, h)).save(buf, "WEBP", quality=80)
    return "data:image/webp;base64," + base64.b64encode(buf.getvalue()).decode()


def build() -> str:
    html = _read("page.html")
    html = re.sub(r"<!--\s*EDITABLE SOURCE.*?-->\s*", "", html, flags=S)

    # inline the stylesheets
    html = html.replace('<link rel="stylesheet" href="garamond.css">',
                        f"<style>{_read('garamond.css')}</style>")
    html = html.replace('<link rel="stylesheet" href="theme.css">',
                        f"<style>{_read('theme.css')}</style>")

    # regenerate the decorative spines strip from the specimen plates (01..14)
    stems, seen = [], set()
    for s in PATH.findall(html):
        if re.match(r"(0[1-9]|1[0-4])_", s) and s not in seen:
            seen.add(s)
            stems.append(s)
    spines = "".join(
        f'<img src="{_thumb(s)}" alt="" aria-hidden="true" loading="lazy">'
        for s in stems)
    html = html.replace('<div class="spines"><!--auto--></div>',
                        f'<div class="spines">{spines}</div>')

    # inline every referenced card at full size
    html = PATH.sub(lambda m: _full(m.group(1)), html)
    return html


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=OUT)
    args = ap.parse_args()
    missing = [s for s in PATH.findall(_read("page.html"))
               if not os.path.exists(os.path.join(CARDS, s + ".webp"))]
    if missing:
        print(f"missing cards: {missing}", file=sys.stderr)
        return 1
    html = build()
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"wrote {os.path.relpath(args.out, ROOT)} "
          f"({os.path.getsize(args.out)/1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
