"""Build the 'framework' companion artifact from its Markdown source.

The bestiary shows the attacks; this shows the defences -- the four guardian
characters (the Guide and the Raven, the Oracle in the Keep, Lean the Proof
Owl, Alloy the Brass Tracker), in the bestiary's own voice and cream/Garamond
look. Words live in docs/framework_artifact/content.md; the illustrations are
docs/figures/framework/standalone/*.png, inlined as downscaled webp.

    uv run python scripts/make_framework_page.py
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

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "docs", "framework_artifact")
IMGS = os.path.join(ROOT, "docs", "figures", "framework", "standalone")
FONT = os.path.join(ROOT, "docs", "bestiary_artifact", "garamond.css")
OUT = os.path.join(ROOT, "artifacts", "framework_page.html")
S = re.DOTALL

STYLE = """
<style>
:root{
  --ground:#EFE7D7; --ground-deep:#E4DAC5; --panel:#F8F3E8;
  --ink:#1E1913; --ink-soft:#4A4034; --muted:#756950; --rule:#CFC2A5;
  --gilt:#8A6716; --shadow:rgba(40,30,12,.16); color-scheme:light;
  --serif:"Garamond Book","Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif;
  --caps:"Garamond Caps","Garamond Book",Georgia,serif;
}
@media (prefers-color-scheme: dark){
  :root{
    --ground:#0B0A08; --ground-deep:#060505; --panel:#16130E;
    --ink:#EEE3CB; --ink-soft:#C3B79B; --muted:#93856A; --rule:#332C21;
    --gilt:#C9A24A; --shadow:rgba(0,0,0,.6); color-scheme:dark;
  }
}
:root[data-theme="dark"]{
  --ground:#0B0A08; --ground-deep:#060505; --panel:#16130E;
  --ink:#EEE3CB; --ink-soft:#C3B79B; --muted:#93856A; --rule:#332C21;
  --gilt:#C9A24A; --shadow:rgba(0,0,0,.6); color-scheme:dark;
}
:root[data-theme="light"]{
  --ground:#EFE7D7; --ground-deep:#E4DAC5; --panel:#F8F3E8;
  --ink:#1E1913; --ink-soft:#4A4034; --muted:#756950; --rule:#CFC2A5;
  --gilt:#8A6716; --shadow:rgba(40,30,12,.16); color-scheme:light;
}
.page{ background:var(--ground); color:var(--ink); font-family:var(--serif);
  font-size:20px; line-height:1.6; -webkit-font-smoothing:antialiased;
  padding:0 18px 6rem; }
.wrap{ max-width:42rem; margin:0 auto; }
.hero{ max-width:52rem; margin:0 auto; padding:clamp(2.5rem,7vw,5.5rem) 0 1.5rem;
  text-align:center; }
.hero__eyebrow{ font-family:var(--caps); text-transform:uppercase;
  letter-spacing:.18em; font-size:.82rem; color:var(--gilt); margin:0 0 .8em; }
.page h1{ color:var(--ink); font-weight:600;
  font-size:clamp(2.6rem,6.5vw,4.4rem); line-height:1.08; letter-spacing:-.01em;
  margin:0; text-wrap:balance; }
.hero__sub{ max-width:34em; margin:1em auto 0; color:var(--ink-soft);
  font-size:1.2rem; text-wrap:balance; }
.hero__rule{ width:min(52rem,100%); margin:2.4rem auto 0; height:1px;
  background:linear-gradient(90deg,transparent,var(--rule) 20%,var(--rule) 80%,transparent); }
.page h2{ color:var(--ink); font-weight:600;
  font-size:clamp(1.7rem,3.4vw,2.3rem); line-height:1.15; text-wrap:balance;
  text-align:center; margin:3.4rem auto 0; max-width:42rem; }
.page p{ margin:1.1em auto; }
.page p, .page li{ max-width:42rem; }
.page strong{ color:var(--ink); font-weight:640; }
.page em{ color:var(--ink-soft); }
figure{ margin:1.8rem auto 0; max-width:60rem; }
figure img{ display:block; width:100%; height:auto; border:1px solid var(--rule);
  border-radius:10px; box-shadow:0 2px 0 var(--rule),0 22px 50px -28px var(--shadow); }
.colophon{ max-width:42rem; margin:4rem auto 0; padding-top:1.2rem;
  border-top:1px solid var(--rule); color:var(--muted); font-size:.9rem;
  text-align:center; }
</style>
"""


def _webp(name, width=1100):
    for f in os.listdir(IMGS):
        if f == name or f.startswith(name.split(".")[0]):
            with Image.open(os.path.join(IMGS, f)) as im:
                im = im.convert("RGB")
                h = round(im.height * width / im.width)
                buf = io.BytesIO()
                im.resize((width, h)).save(buf, "WEBP", quality=82)
            return "data:image/webp;base64," + base64.b64encode(buf.getvalue()).decode()
    raise SystemExit(f"framework image not found: {name}")


def build():
    raw = open(os.path.join(SRC, "content.md"), encoding="utf-8").read()
    raw = re.sub(r"<!--.*?-->", "", raw, flags=S)
    m = re.match(r"^\s*---\n(.*?)\n---\n(.*)$", raw, S)
    meta = yaml.safe_load(m.group(1))
    body = markdown.markdown(m.group(2).strip(), extensions=["sane_lists"])

    # inline images and wrap each in a <figure>
    def img(mo):
        src = re.search(r'src="([^"]+)"', mo.group(0)).group(1)
        alt = (re.search(r'alt="([^"]*)"', mo.group(0)) or ["", ""])[1]
        return (f'<figure><img loading="lazy" alt="{alt}" '
                f'src="{_webp(os.path.basename(src))}"></figure>')
    body = re.sub(r"<p>\s*(<img[^>]*>)\s*</p>", lambda mo: img(mo), body)

    font = open(FONT, encoding="utf-8").read()
    hero = (f'<header class="hero">'
            f'<p class="hero__eyebrow">{meta.get("eyebrow","")}</p>'
            f'<h1>{meta["title"]}</h1>'
            f'<p class="hero__sub">{meta.get("subtitle","").strip()}</p>'
            f'<div class="hero__rule"></div></header>')
    colophon = ('<div class="colophon">A companion to the bestiary · '
                'safe-tre-agent · research prototype on synthetic data.</div>')
    n = body.count("<figure>")
    if n != 4:
        raise SystemExit(f"expected 4 illustrations, embedded {n}")
    return (f'<title>{meta["title"]}</title>\n<style>{font}</style>\n{STYLE}\n'
            f'<div class="page">{hero}<div class="wrap">{body}</div>{colophon}</div>\n')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()
    html = build()
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    open(a.out, "w", encoding="utf-8").write(html)
    print(f"wrote {os.path.relpath(a.out, ROOT)} ({os.path.getsize(a.out)/1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
