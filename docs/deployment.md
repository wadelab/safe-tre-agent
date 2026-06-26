# Deployment

Target: a single host (e.g. `d2-1`) inside a **safepod**: data and server are
physically controlled, and researchers communicate only through a restricted
channel. There is no public internet path to the app. The host binds
`127.0.0.1`; `tailscale serve` provides TLS and the authenticated identity.

## Safepod topology

```mermaid
flowchart LR
    subgraph TN["restricted channel"]
        U1["laptop"] -.-> TS
        U2["phone"] -.-> TS
    end
    subgraph D2["safepod: d2-1"]
        TS["tailscale serve<br/>HTTPS + identity header"] --> APP["uvicorn :8800<br/>127.0.0.1 only"]
        APP --> ENG["DuckDB (read-only)"]
        DATA[("row-level data")] -. load .- ENG
        APP --> LLM["local model runtime<br/>120B-class target"]
        APP --> LOG[("audit log<br/>/var/lib/safetre")]
    end
    LOG -. anchor .-> ANCHOR["off-pod audit anchor"]
    style D2 fill:#eef6ff,stroke:#164e75,color:#17202A
    style TN fill:#f6f8fb,stroke:#64748b,color:#17202A
    style DATA fill:#fdeaea,stroke:#c62828,color:#17202A
```

## Quick run (foreground)

```bash
uv sync --all-extras
uv run uvicorn safetre_web.app:app --host 127.0.0.1 --port 8800   # or: scripts/run_web.sh
```

Then expose to the tailnet:

```bash
tailscale serve --bg 8800
# -> https://d2-1.<tailnet>.ts.net   (TLS terminated by tailscale; identity header injected)
```

For real data, use the production settings below rather than the foreground
command.

## Production (systemd)

A hardened unit ships in [`deploy/safetre-web.service`](../deploy/safetre-web.service).

```bash
# in the repo on d2-1
uv sync --all-extras                 # creates .venv the unit points at

sudo cp deploy/safetre-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now safetre-web
systemctl status safetre-web
systemd-analyze security safetre-web   # should report a low exposure score
```

The unit runs as a `DynamicUser` with `ProtectSystem=strict`, a private tmp,
restricted address families and syscalls, no capabilities, and writes only to its
`StateDirectory` (`/var/lib/safetre`). Adjust `WorkingDirectory`, the `.venv`
path and `--port` to your host.

The shipped unit also sets the app to require the restricted channel and a
tailnet identity. With `IPAddressDeny=any` plus localhost allows, the process
cannot accidentally talk to arbitrary network destinations. If your local model
runs on a different fixed address inside the safepod, add that address to the
systemd IP allowlist. Add it to `SAFETRE_CHANNEL_ALLOW_NETS` only if that same
host is also meant to call the web app as an approved ingress peer.

## Access control (Safe People)

1. **tailscale ACLs** decide which tailnet users/devices can reach the service —
   the auditable, policy-as-code outer gate.
2. **`SAFETRE_ALLOWLIST`** (comma-separated logins) is the app-level inner gate.
   When set, only those logins may run queries; everyone else gets `403`.

```bash
SAFETRE_ALLOWLIST="alex@example.org,sam@example.org" ...
```

Because the app binds `127.0.0.1`, the `Tailscale-User-Login` header can only be
supplied by the local tailscale proxy — a remote client cannot forge it.

## Restricted channel

The application checks the real peer address on every request before it runs
identity, planning, or query execution.

Recommended production defaults:

```bash
SAFETRE_RESTRICTED_CHANNEL=1
SAFETRE_CHANNEL_ALLOW_NETS=127.0.0.1/32,::1/128
SAFETRE_REQUIRE_IDENTITY=1
```

This matches the `tailscale serve -> localhost uvicorn` topology. If you place a
separate gateway in front of the safepod, add only that gateway's fixed address
or CIDR. Do not rely on `X-Forwarded-For`; the app ignores forwarded headers for
channel decisions.

## Configuration reference

All configuration is via environment variables.

| Variable | Default | Purpose |
|---|---|---|
| `SAFETRE_LLM` | `mock` | `mock` (deterministic MockPlanner) or `real` (local model planner) |
| `SAFETRE_LLM_BASE_URL` | `http://127.0.0.1:8000/v1` | OpenAI-compatible local model endpoint |
| `SAFETRE_LLM_API_KEY` | `local` | bearer token for the local endpoint, if required |
| `SAFETRE_LLM_MODEL` | `local-120b` | runtime model id; default documents the 120B-class planning assumption |
| `SAFETRE_LLM_TEMPERATURE` | `0` | deterministic planning |
| `SAFETRE_LLM_TIMEOUT` | `60` | model request timeout in seconds |
| `SAFETRE_ALLOWED_LLM_HOSTS` | `localhost,127.0.0.1,::1` | comma-separated model endpoint hosts allowed without remote opt-in |
| `SAFETRE_ALLOW_REMOTE_LLM` | unset | set `1` only for synthetic-data remote endpoint experiments |
| `SAFETRE_ALLOWLIST` | – (open) | comma-separated Safe People logins |
| `SAFETRE_REQUIRE_IDENTITY` | unset | set `1` in production to deny requests without tailnet identity |
| `SAFETRE_RESTRICTED_CHANNEL` | `1` | reject requests outside the approved channel unless set to `0` |
| `SAFETRE_CHANNEL_ALLOW_NETS` | `127.0.0.1/32,::1/128` | comma-separated CIDRs allowed to reach the app |
| `SAFETRE_AUDIT_DB` | `audit.db` | path to the hash-chained audit log |
| `SAFETRE_AUDIT_KEY` | generated dev key | HMAC key; provide from an off-box secret in production |
| `PORT` | `8800` | used by `scripts/run_web.sh` |

Legacy `OPENAI_BASE_URL`, `OPENAI_API_KEY`, and `SAFETRE_MODEL` are still read
as fallbacks, but new deployments should use the `SAFETRE_LLM_*` names. The
model never sees secrets and never needs network beyond the local model
endpoint. See [`.env.example`](../.env.example) and [Model runtime](model-runtime.md).

## Audit log operations

- The log is an append-only, hash-chained SQLite database at `SAFETRE_AUDIT_DB`.
- Verify integrity at any time: `GET /api/audit/verify` → `{"chain_intact": true}`,
  or in code `AuditLog(path).verify()`.
- **Mirror it off-box** (rsync/litestream to a separate host) so a compromise of
  `d2-1` cannot rewrite history. (Phase 2.)
- Back up before upgrades; the chain is portable.

## Upgrades

```bash
git pull
uv sync --all-extras          # re-pins from uv.lock
sudo systemctl restart safetre-web
```

Run the test suite (`uv run pytest -q`) and `systemd-analyze security` after any
change that touches the request path or the unit file.

See [Safepod model](safepod.md) for the physical controls around the host:
locked enclosure, tamper evidence, disk encryption, port/radio disablement,
maintenance logging, and off-pod audit anchoring.
