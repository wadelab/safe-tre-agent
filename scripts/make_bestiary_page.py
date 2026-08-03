"""Render `docs/bestiary.md` as a standalone illustrated web page.

The field guide is the source of truth. This script turns it into one
self-contained HTML page — every card embedded as a `data:` URI, no external
requests — styled in the GOV.UK Design System visual language used by the web
app (type scale, links, inset/warning components, phase-banner tag), minus the
Crown logo and wordmark: this is a research prototype, not a government
service. Because it renders the live markdown, the page cannot drift from the
repository the way a hand-built copy did: re-run it after any edit to
`docs/bestiary.md` or the cards.

    uv run --group decks python scripts/make_bestiary_page.py

Cards are read from `docs/figures/bestiary/`. The committed masters are `.png`;
the web page prefers the smaller `.webp` derivative when present and falls back
to the `.png` otherwise.
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import sys

import markdown

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "docs", "bestiary.md")
CARDS = os.path.join(ROOT, "docs", "figures", "bestiary")
OUT = os.path.join(ROOT, "artifacts", "bestiary_page.html")

# The field guide links to sibling mkdocs pages; those routes do not exist off
# the docs site, so relative *.md links become plain text.
MD_LINK = re.compile(r'<a href="[^"]*\.md(?:#[^"]*)?">([^<]*)</a>')
IMG = re.compile(r'<img\b[^>]*\bsrc="(?:\.\./)?figures/bestiary/([^"]+)"[^>]*>')


def _data_uri(filename: str) -> tuple[str, str]:
    """Return (mime, base64) for a card, preferring the webp derivative."""
    stem = os.path.splitext(filename)[0]
    for ext, mime in ((".webp", "image/webp"), (".png", "image/png")):
        path = os.path.join(CARDS, stem + ext)
        if os.path.exists(path):
            with open(path, "rb") as fh:
                return mime, base64.b64encode(fh.read()).decode("ascii")
    raise FileNotFoundError(f"no card for {filename} in {CARDS}")


def _inline_images(html: str) -> str:
    def repl(m):
        filename = m.group(1)
        mime, b64 = _data_uri(filename)
        name = os.path.splitext(filename)[0].split("_", 1)[-1].replace("_", " ")
        return (f'<img class="card" loading="lazy" '
                f'alt="Card illustration: {name.title()}" '
                f'src="data:{mime};base64,{b64}">')
    return IMG.sub(repl, html)


def _wrap_tables(html: str) -> str:
    return (html.replace("<table>", '<div class="tw"><table class="tbl">')
                .replace("</table>", "</table></div>"))


def _mark_galleries(html: str) -> str:
    """A paragraph that is nothing but several cards is a specimen plate."""
    def repl(m):
        body = m.group(1)
        if body.count("<img") >= 3 and re.sub(r"<img[^>]*>|\s", "", body) == "":
            return f'<div class="plate">{body}</div>'
        return m.group(0)
    return re.sub(r"<p>(.*?)</p>", repl, html, flags=re.DOTALL)


STYLE = """
<style>
:root{
  --black:#0b0c0c; --white:#fff; --blue:#1d70b8; --dblue:#003078;
  --purple:#4c2c92; --green:#00703c; --red:#d4351c; --grey:#505a5f;
  --mid:#b1b4b6; --light:#f3f2f1; --focus:#fd0;
  --sans:"GDS Transport",arial,"Helvetica Neue",Helvetica,sans-serif;
}
.page{background:var(--white); color:var(--black); font-family:var(--sans);
  font-size:19px; line-height:1.3158; -webkit-font-smoothing:antialiased;
  padding:0 15px 60px;}
.wrap{max-width:41rem; margin:0 auto;}
.page *{box-sizing:border-box;}

/* Phase banner */
.phase{max-width:41rem; margin:0 auto; padding:10px 0;
  border-bottom:1px solid var(--mid); display:flex; gap:10px;
  align-items:baseline; flex-wrap:wrap;}
.tag{display:inline-block; font-size:.85rem; font-weight:700; line-height:1;
  letter-spacing:.05em; text-transform:uppercase; color:#144e81;
  background:#d2e2f1; padding:5px 8px 4px;}
.phase span{font-size:.94rem; color:var(--grey);}

/* Type scale (GOV.UK) */
.page h1,.page h2,.page h3{font-weight:700; margin:0 0 20px;
  text-wrap:balance;}
.page h1{font-size:2.5rem; line-height:1.09; margin-top:24px;}
.page h2{font-size:1.85rem; line-height:1.11; margin-top:44px;}
.page h3{font-size:1.35rem; line-height:1.2; margin-top:32px; margin-bottom:12px;}
.page p,.page li{font-size:1.1875rem; margin:0 0 20px; max-width:38em;}
.page ul,.page ol{margin:0 0 20px; padding-left:20px;}
.page li{margin-bottom:8px;}

/* Links + GOV.UK focus state */
.page a{color:var(--blue); text-decoration:underline;
  text-decoration-thickness:max(1px,.0625rem); text-underline-offset:.1em;}
.page a:hover{color:var(--dblue); text-decoration-thickness:3px;}
.page a:visited{color:var(--purple);}
.page a:focus{outline:3px solid transparent; color:var(--black);
  background:var(--focus); box-shadow:0 -2px var(--focus),0 4px var(--black);
  text-decoration:none;}
.page strong{font-weight:700;}
.page em{font-style:italic; color:var(--grey);}

/* Section rule + horizontal <hr> */
.page hr{border:0; height:1px; background:var(--mid); margin:40px 0;}

/* Standfirst */
.wrap>p:first-of-type{font-size:1.4rem; line-height:1.25; color:var(--grey);
  margin-bottom:32px;}

/* Inset text (blockquote) */
.page blockquote{margin:24px 0; padding:15px 0 15px 20px;
  border-left:5px solid var(--mid); color:var(--black); font-style:normal;}
.page blockquote p{max-width:none;}

/* Code / manifest tags */
.page code{font-family:ui-monospace,"Cascadia Mono",Consolas,monospace;
  font-size:.85em; background:var(--light); padding:1px 4px;
  word-break:break-word;}

/* Warning / admonition -> GOV.UK inset with coloured rule */
.admonition{margin:24px 0; padding:15px 20px; background:var(--light);
  border-left:5px solid var(--red);}
.admonition>*{max-width:none;}
.admonition-title{font-weight:700; margin:0 0 6px!important;
  text-transform:none;}

/* Cards */
.card{display:block; border:1px solid var(--mid);}
.page p>.card{float:right; width:min(44%,240px); margin:4px 0 16px 24px;}
@media (max-width:620px){.page p>.card{float:none; width:75%; margin:16px auto;}}
.plate{display:grid;
  grid-template-columns:repeat(auto-fill,minmax(120px,1fr));
  gap:14px; margin:24px 0 32px; clear:both;}
.plate .card{float:none; width:100%; margin:0;}

/* Tables (GOV.UK) */
.tw{overflow-x:auto; margin:24px 0;}
.tbl{border-collapse:collapse; width:100%; min-width:44rem;
  font-size:1rem; line-height:1.31;}
.tbl th,.tbl td{text-align:left; vertical-align:top; padding:11px 20px 9px 0;
  border-bottom:1px solid var(--mid);}
.tbl thead th{border-bottom:2px solid var(--mid); font-weight:700;}
.tbl td:first-child,.tbl th:first-child{font-weight:700;}
.tbl code{background:transparent; padding:0;}
.tbl em{color:var(--grey);}

/* Colophon */
.colophon{max-width:41rem; margin:48px auto 0; padding-top:20px;
  border-top:1px solid var(--mid); color:var(--grey); font-size:.95rem;}
</style>
"""

PHASE = ('<div class="phase"><strong class="tag">Prototype</strong>'
         '<span>Synthetic data &mdash; not a live government service.</span>'
         '</div>')


def build() -> str:
    with open(SRC, encoding="utf-8") as fh:
        text = fh.read()
    body = markdown.markdown(
        text, extensions=["tables", "admonition", "attr_list", "sane_lists"])
    body = _inline_images(body)
    body = _wrap_tables(body)
    body = _mark_galleries(body)
    body = MD_LINK.sub(r"\1", body)
    colophon = ('<div class="colophon">Rendered from '
                "<code>docs/bestiary.md</code> &mdash; the field guide is the "
                "source of record.</div>")
    return (f"<title>A bestiary of caged beasts</title>\n{STYLE}\n"
            f'<div class="page">{PHASE}'
            f'<div class="wrap">{body}</div>{colophon}</div>\n')


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=OUT)
    args = ap.parse_args()
    if not os.path.isdir(CARDS):
        print(f"no cards at {os.path.relpath(CARDS, ROOT)}", file=sys.stderr)
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
