# Evidence checklist

A demo only counts as evidence if someone else can tie what you saw to a
commit and reproduce it. Record this bundle every time you run the demo for an
audience, cut a release, or report a result — it is the lightweight version of
the [test deployment evidence bundle](test-deployment.md#7-evidence-bundle).

## What to record

| Item | How to get it |
|---|---|
| Commit | `git rev-parse HEAD` |
| Environment lock | `sha256sum uv.lock` |
| Host and OS | `uname -a` (or equivalent) |
| Planner mode | `mock` or `real`; if the endpoint was remote, say so (remote is synthetic-data-only) |
| Test suite | `uv run pytest -q` |
| Red-team | `uv run python redteam/run_redteam.py` — the summary line |
| SAST | `uv run bandit -q -r safetre safetre_web` |
| Dependency audit | `uv run pip-audit` |
| Docs build | `uv run --group docs mkdocs build --strict` |
| Audit chain | `curl http://127.0.0.1:8800/api/audit/verify` |
| Restricted channel | whether the tailnet rehearsal was run ([test deployment § 5](test-deployment.md#5-rehearse-restricted-channel-access)) |
| Date | when the run happened |

Do not attach generated artifacts (`data/*.csv`, `audit.db*`, `site/`,
`redteam/results.csv`) — the point is that anyone can regenerate them from the
commit.

## Copyable template

Paste into an issue comment or release note and fill in:

```markdown
### Demo evidence — YYYY-MM-DD

- commit: `<sha>` · uv.lock sha256: `<hash>`
- host: `<hostname, OS>` · planner mode: `<mock|real>` · endpoint: `<local|remote (synthetic-data-only)>`
- [ ] tests pass (`uv run pytest -q`)
- [ ] red-team: all attacks neutralised (`uv run python redteam/run_redteam.py`)
- [ ] SAST clean (`uv run bandit -q -r safetre safetre_web`)
- [ ] dependency audit clean (`uv run pip-audit`)
- [ ] docs build clean (`uv run --group docs mkdocs build --strict`)
- [ ] audit chain intact (`/api/audit/verify` → `{"chain_intact": true}`)
- [ ] restricted-channel rehearsal: yes / no
- deviations from the runbook: none / <list>
```

A run with a failing box is still worth recording — say what failed and why.
An honest evidence trail with known deviations beats a clean-looking one that
skips the awkward line.

## Status framing

When citing results, keep the same framing the docs use: what is built and
tested is recorded in the [write-up](writeup.md) and the
[hardening log](hardening-log.md), what is deliberately not yet done
is in the [roadmap](roadmap.md), and nothing in a synthetic-data demo implies
readiness for real data — that bar is the [certification](certification.md)
and [safepod](safepod.md) pages.
