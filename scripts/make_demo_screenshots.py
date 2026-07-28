"""Capture the documentation screenshot set for the public demo tour.

Starts a throwaway web server on its own port with the deterministic mock
planner and a fresh audit log, screenshots each demo state with headless
Chrome, and writes deterministically named PNGs into docs/figures/. Anyone
who clones the repo can regenerate the exact same set:

    uv run python scripts/make_data.py            # once, if data/ is absent
    uv run python scripts/make_demo_screenshots.py

The mock planner is the explicit tests/CI opt-in (SAFETRE_LLM=mock) chosen
here so the captures are reproducible without a model endpoint — the same
reason CI's pa11y job uses it. It is never a silent fallback for the live app.

The server binds 127.0.0.1:8801 (not 8800) so a running demo server is left
untouched, and audits into a temporary file so the repo audit DB is not
polluted with capture traffic.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIGURES = os.path.join(ROOT, "docs", "figures")
PORT = 8801
BASE = f"http://127.0.0.1:{PORT}"

# One entry per demo state. Queries are chosen so the deterministic mock
# planner reproduces each gateway outcome; the tour page explains each one.
SHOTS = {
    "demo-home": "/",
    "demo-released": "/#q=mean%20spend%20by%20age%20band",
    "demo-redacted": "/#q=mean%20spend%20by%20age%20band,%20region%20and%20device%20os",
    "demo-denied": "/#q=show%20mean%20wellbeing%20per%20donor",
}


def find_chrome() -> str:
    for path in ("/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"):
        if os.path.exists(path):
            return path
    sys.exit("no chrome/chromium found; install one to capture screenshots")


def wait_healthy(timeout_s: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(BASE + "/healthz", timeout=2)
            return
        except Exception:
            time.sleep(0.5)
    sys.exit(f"throwaway server did not become healthy at {BASE}")


def main() -> None:
    if not os.path.exists(os.path.join(ROOT, "data", "donors.csv")):
        sys.exit("data/ is missing — run: uv run python scripts/make_data.py")
    chrome = find_chrome()

    # Scrub ambient SAFETRE_* config so the capture server is exactly the
    # documented configuration and nothing else.
    env = {k: v for k, v in os.environ.items() if not k.startswith("SAFETRE_")}
    with tempfile.TemporaryDirectory(prefix="safetre-shots-") as tmp:
        env["SAFETRE_LLM"] = "mock"
        # headless Chrome screenshots cannot click, so the capture server
        # re-enables prefill auto-run. It is off in every real deployment
        # (hardening #50) and this process is thrown away afterwards.
        env["SAFETRE_ALLOW_PREFILL_AUTORUN"] = "1"
        env["SAFETRE_AUDIT_DB"] = os.path.join(tmp, "audit.db")
        server = subprocess.Popen(
            ["uv", "run", "uvicorn", "safetre_web.app:app",
             "--host", "127.0.0.1", "--port", str(PORT)],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            wait_healthy()
            os.makedirs(FIGURES, exist_ok=True)
            for name, path in SHOTS.items():
                out = os.path.join(FIGURES, name + ".png")
                subprocess.run(
                    [chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                     "--window-size=1280,1400", "--run-all-compositor-stages-before-draw",
                     "--virtual-time-budget=9000",
                     f"--screenshot={out}", BASE + path],
                    check=True, stderr=subprocess.DEVNULL)
                print(f"captured {name} -> {os.path.relpath(out, ROOT)}")
        finally:
            server.terminate()
            server.wait(timeout=10)


if __name__ == "__main__":
    main()
