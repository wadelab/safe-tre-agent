"""Build the bestiary artifact from its Markdown source.

The words live in `docs/bestiary_artifact/content.md` (edit that); the design
is `theme.css`, the fonts `garamond.css`, the card art `docs/figures/bestiary/`.
This renders them into one self-contained HTML page -- every image a `data:`
URI, no external requests -- ready to publish as an Artifact.

    uv run python scripts/make_bestiary_page.py

content.md is YAML front-matter (title, eyebrow, subtitle, stats, legend) plus
a body of `# Heading <!--kind-->` sections. Prose/reserve/closing sections are
free Markdown; plates/hunts/zoo/loose/retired carry `### items` with `- card:`
etc. See the header comment in content.md.
"""
from __future__ import annotations
import argparse
import base64
import io
import os
import re
import sys
import yaml
import markdown
from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import project_counts

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "docs", "bestiary_artifact")
CARDS = os.path.join(ROOT, "docs", "figures", "bestiary")
OUT = os.path.join(ROOT, "artifacts", "bestiary_page.html")
S = re.DOTALL
ROMAN = ["I","II","III","IV","V","VI","VII","VIII","IX","X","XI","XII","XIII",
         "XIV","XV","XVI","XVII","XVIII","XIX","XX"]


def _read(name): 
    with open(os.path.join(SRC, name), encoding="utf-8") as fh:
        return fh.read()



def _full(stem):
    with open(os.path.join(CARDS, stem + ".webp"), "rb") as fh:
        return "data:image/webp;base64," + base64.b64encode(fh.read()).decode()

def _thumb(stem, w=150):
    with Image.open(os.path.join(CARDS, stem + ".webp")) as im:
        im = im.convert("RGB")
        h = round(im.height * w / im.width)
        buf = io.BytesIO()
        im.resize((w, h)).save(buf, "WEBP", quality=80)
    return "data:image/webp;base64," + base64.b64encode(buf.getvalue()).decode()

def _card(stem, cls="card"):
    if not stem:
        return ""
    name = stem.split("_", 1)[-1].replace("_", " ").title()
    return (f'<img class="{cls}" loading="lazy" alt="Card illustration: {name}" '
            f'src="{_full(stem)}">')

def _inline(t):
    """Inline markup for short fields: **bold**, *em*, [#ref] -> spans."""
    t = re.sub(r"\[([^\]]+)\]", r'<span class="ref">\1</span>', t)
    t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
    t = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"<em>\1</em>", t)
    return t

def _md(text):
    """Free Markdown -> HTML, then turn [#ref] tags into ref spans."""
    html = markdown.markdown(text.strip(), extensions=["sane_lists"])
    return re.sub(r"\[(#[^\]]+)\]", r'<span class="ref">\1</span>', html)


def _split_sections(body):
    parts = re.split(r"(?m)^#\s+(.*?)\s*<!--(\w+)-->\s*$", body)
    # parts: [pre, title1, kind1, body1, title2, kind2, body2, ...]
    out = []
    for i in range(1, len(parts), 3):
        out.append((parts[i].strip(), parts[i+1], parts[i+2]))
    return out

def _items(body):
    """Split a section body into (intro_md, [(head, item_body), ...]) on '### '."""
    parts = re.split(r"(?m)^###\s+(.*?)\s*$", body)
    intro = parts[0].strip()
    items = [(parts[i].strip(), parts[i+1]) for i in range(1, len(parts), 2)]
    return intro, items

def _fields(item_body):
    """Pull `- key: value` bullets, `**Label:** ...` lines, and prose paras."""
    fields, labels, prose = {}, {}, []
    for block in re.split(r"\n\s*\n", item_body.strip()):
        b = block.strip()
        if not b:
            continue
        mb = re.match(r"-\s*(\w+):\s*(.*)", b, S)
        ml = re.match(r"\*\*(\w+):\*\*\s*(.*)", b, S)
        if mb and "\n- " in ("\n" + b):     # a bullet list of fields
            for line in b.splitlines():
                m = re.match(r"-\s*(\w+):\s*(.*)", line)
                if m:
                    fields[m.group(1).lower()] = m.group(2).strip()
            continue
        if mb:
            fields[mb.group(1).lower()] = re.sub(r"\s+", " ", mb.group(2)).strip()
        elif ml:
            labels[ml.group(1).lower()] = re.sub(r"\s+", " ", ml.group(2)).strip()
        else:
            prose.append(re.sub(r"\s+", " ", b))
    return fields, labels, prose


def build():
    raw = _read("content.md")
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", raw, S)
    meta = yaml.safe_load(m.group(1))
    body = m.group(2)

    # hero
    stats = "".join(f"<span>{_inline(s)}</span>" for s in meta.get("stats", []))
    plate_stems = []   # collected for the spine strip

    html = [
      f'<title>{meta["title"]}</title>',
      f'<style>{_read("garamond.css")}</style>',
      f'<style>{_read("theme.css")}</style>',
      '<header class="hero"><div class="wrap">',
      f'<p class="hero__eyebrow">{_inline(meta.get("eyebrow",""))}</p>',
      f'<h1>{meta["title"]}</h1>',
      f'<p class="hero__sub">{_inline(re.sub(r" +"," ",meta.get("subtitle","").replace(chr(10)," ")).strip())}</p>',
      f'<div class="hero__meta">{stats}</div>',
      '<div class="spines" data-spines></div>',
      '</div></header>',
    ]

    for title, kind, sbody in _split_sections(body):
        if kind in ("prose", "closing"):
            rendered = _md(sbody)
            ol = re.search(r"<ol>.*?</ol>", rendered, S)
            ol_html = ol.group(0).replace("<ol>", '<ol class="habits">') if ol else ""
            if ol_html:
                # .habits li is a number+content grid; the content must be one
                # grid item (a span), and the CSS styles <b>, not <strong>.
                ol_html = re.sub(r"<li>(.*?)</li>",
                                 lambda m: "<li><span>" + m.group(1).strip() + "</span></li>",
                                 ol_html, flags=S)
                ol_html = ol_html.replace("<strong>", "<b>").replace("</strong>", "</b>")
            head = rendered.replace(ol.group(0), "") if ol else rendered
            html.append(f'<section><div class="wrap"><div class="head"><h2>{title}</h2>'
                        f'{head}</div>{ol_html}</div></section>')
        elif kind == "reserve":
            intro, items = _items(sbody)
            tri = "".join(f"<div><h3>{_inline(h)}</h3>{_md(b)}</div>" for h, b in items)
            legend = "".join(
                f'<li><span class="chip chip--{k}">{_inline(lab)}</span>'
                f'<span>{_inline(d)}</span></li>' for k, lab, d in meta.get("legend", []))
            html.append(f'<section><div class="wrap"><div class="head"><h2>{title}</h2>'
                        f'{_md(intro)}</div><div class="tri">{tri}</div>'
                        f'<ul class="legend">{legend}</ul></div></section>')
        elif kind == "plates":
            intro, items = _items(sbody)
            arts = []
            for n, (name, ib) in enumerate(items):
                f, _lab, prose = _fields(ib)
                plate_stems.append(f.get("card", ""))
                ck, _sep, ctext = f.get("cage", "").partition(" — ")
                cage_label = {"behavioural": "behavioural pen",
                              "deterministic": "deterministic gate",
                              "not": "not expressible"}.get(ck.strip(), ck.strip())
                story = "".join(f"<p>{_inline(p)}</p>" for p in prose)
                arts.append(
                  f'<article class="plate" id="plate-{n+1}">'
                  f'<div class="plate__mount">{_card(f.get("card",""))}</div>'
                  f'<div class="plate__body"><p class="plate__num">Plate {ROMAN[n]}</p>'
                  f'<h3>{_inline(name)}</h3>'
                  f'<p class="wants"><span class="lbl">Wants</span>{_inline(f.get("wants",""))}</p>'
                  f'<div class="story">{story}</div>'
                  f'<div class="cage cage--{ck.strip()}">'
                  f'<p class="lbl">The cage <em>{cage_label}</em></p>'
                  f'<p>{_inline(ctext.strip())}</p></div></div></article>')
            html.append(f'<section><div class="wrap"><div class="head"><h2>{title}</h2>'
                        f'{_md(intro)}</div><div class="plates">{"".join(arts)}</div>'
                        f'</div></section>')
        elif kind == "hunts":
            intro, items = _items(sbody)
            arts = []
            for name, ib in items:
                f, lab, prose = _fields(ib)
                ps = "".join(f"<p>{_inline(p)}</p>" for p in prose)
                arts.append(
                  f'<article class="hunt">'
                  f'<div class="plate__mount plate__mount--wide">{_card(f.get("card",""))}</div>'
                  f'<div class="hunt__body"><h3>{_inline(name)}</h3>{ps}'
                  f'<p class="lesson">{_inline(lab.get("lesson",""))}</p></div></article>')
            html.append(f'<section><div class="wrap"><div class="head"><h2>{title}</h2>'
                        f'{_md(intro)}</div><div class="hunts">{"".join(arts)}</div>'
                        f'</div></section>')
        elif kind == "zoo":
            f, lab, prose = _fields(sbody)
            ps = "".join(f"<p>{_inline(p)}</p>" for p in prose)
            html.append(
              f'<section class="zoo"><div class="wrap zoo__inner">'
              f'<div class="plate__mount">{_card(f.get("card",""))}</div>'
              f'<div class="zoo__body"><h2>{title}</h2>'
              f'<p class="zoo__lead">{_inline(lab.get("lead",""))}</p>{ps}'
              f'<p class="zoo__cage">{_inline(lab.get("cage",""))}</p></div></div></section>')
        elif kind in ("loose", "retired"):
            intro, items = _items(sbody)
            lis = []
            for name, ib in items:
                f, lab, prose = _fields(ib)
                ref = re.search(r"\[([^\]]+)\]\s*$", name)
                nm = re.sub(r"\s*\[[^\]]+\]\s*$", "", name)
                h4 = _inline(nm) + (f' <span class="ref">{ref.group(1)}</span>' if ref else "")
                ps = "".join(f"<p>{_inline(p)}</p>" for p in prose)
                lis.append(f'<li class="{kind}"><div class="plate__mount plate__mount--small">'
                           f'{_card(f.get("card",""))}</div><h4>{h4}</h4>{ps}</li>')
            html.append(f'<section><div class="wrap"><div class="head"><h2>{title}</h2>'
                        f'{_md(intro)}</div><ul class="loose-grid">{"".join(lis)}</ul>'
                        f'</div></section>')
        elif kind == "footer":
            html.append(f'<footer><div class="wrap">{_md(sbody)}</div></footer>')
        else:
            raise ValueError(f"unknown section kind {kind!r} for {title!r}")

    # spines: thumbnails of the plate cards
    spines = "".join(f'<img src="{_thumb(s)}" alt="" aria-hidden="true" loading="lazy">'
                     for s in plate_stems if s)
    page = "\n".join(html).replace('<div class="spines" data-spines></div>',
                                    f'<div class="spines">{spines}</div>')

    # live counts: {{findings}} etc. in content.md are filled from the repo,
    # so the hero and footer update as the project changes (never hand-typed).
    counts = dict(project_counts.counts(),
                  specimens=page.count('alt="Card illustration:'),
                  at_large=page.count('<li class="loose">'))
    for k, v in counts.items():
        page = page.replace("{{" + k + "}}", str(v))
    leftover = sorted(set(re.findall(r"\{\{(\w+)\}\}", page)))
    if leftover:
        raise SystemExit(f"unknown count placeholder(s) in content.md: {leftover}")
    print("  counts:", ", ".join(f"{k}={v}" for k, v in counts.items()))

    # validate: nothing silently dropped
    ncards = page.count('alt="Card illustration:')
    if ncards != 24:
        raise SystemExit(f"expected 24 specimen cards, got {ncards} -- content.md drift")
    return page


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=OUT)
    args = ap.parse_args()
    page = build()
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(page)
    print(f"wrote {os.path.relpath(args.out, ROOT)} ({os.path.getsize(args.out)/1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
