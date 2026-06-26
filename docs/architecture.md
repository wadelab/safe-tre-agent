# Architecture

## Design principle

The large language model is **untrusted**. It can be wrong, or be prompt-injected
by the data it reads. So it is never given the ability to execute code or write
SQL. Its only output is a **proposal** — a `QuerySpec` — which the rest of the
system validates and executes deterministically. Every component after the model
is auditable and testable in isolation.

In the two-LLM deployment, the outside LLM uses a public tool manifest to plan,
and the safepod independently validates the proposed tool call. An optional
inside LLM may advise on statistical appropriateness or escalation, but it does
not authorize execution. See [Tool manifest](tool-manifest.md).

## Components

```mermaid
flowchart TB
    R(["🧑‍🔬 Researcher<br/>natural language"]) ==> WEB

    subgraph ENC["🔒 Trusted Research Environment (host process)"]
        direction TB
        WEB["FastAPI web layer<br/>identity · session · CSP"] --> VET["intent vetting"]
        VET --> PLAN["planner<br/>LLM (untrusted) → QuerySpec"]
        PLAN --> VAL["QuerySpec validation<br/>Pydantic allowlist"]
        VAL --> ENG["query engine<br/>parameterised SQL"]
        ENG --> DB[("DuckDB<br/>read-only views")]
        DATA[("🗄️ row-level<br/>synthetic data")] -. load .-> DB
        ENG --> GW["safe-outputs gateway<br/>min cell · suppression · egress"]
        GW --> AUD["session auditor<br/>differencing · budget"]
        AUD --> HITL{"human-in-the-loop"}
        HITL --> LOG[("hash-chained<br/>audit log")]
    end

    HITL ==>|approved aggregate| OUT(["📊 result"])
    HITL -.->|deny| X(["⛔ blocked"])

    style ENC fill:#eef6ff,stroke:#164e75,color:#17202A
    style DATA fill:#fdeaea,stroke:#c62828,color:#17202A
    style PLAN fill:#fdeaea,stroke:#c62828,color:#17202A
    style OUT fill:#e7f5ec,stroke:#2e7d32,color:#17202A
    style X fill:#fdeaea,stroke:#c62828,color:#17202A
```

Red = untrusted (the model, the raw data). Everything else is deterministic and
covered by tests.

| Component | File | Responsibility |
|---|---|---|
| Web layer | `safetre_web/app.py` | routes, Pydantic request validation, security headers |
| Identity | `safetre_web/identity.py` | tailscale login → Safe People allowlist |
| Session | `safetre_web/session.py` | per-user `SessionAuditor` + history |
| Vetting | `safetre/analyst.py::vet_request` | block obviously hostile intent |
| Planner | `safetre/planner.py` | untrusted LLM → `QuerySpec` (+ `MockPlanner`) |
| Manifest | `safetre/manifest.py` | public capability contract for outside planners |
| QuerySpec | `safetre/query.py` | the validated allowlist boundary |
| Engine | `safetre/engine.py` | spec → parameterised DuckDB SQL |
| Gateway | `safetre/disclosure.py` | min cell size, suppression, egress checks |
| Auditor | `safetre/disclosure.py::SessionAuditor` | differencing, query budget |
| Audit log | `safetre/audit.py` | tamper-evident hash chain |

## Request lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor R as Researcher
    participant W as Web layer
    participant P as Planner (LLM)
    participant V as Validation
    participant E as Engine (DuckDB)
    participant G as Gateway + Auditor
    participant L as Audit log
    R->>W: POST /api/query {q}
    W->>W: identity + length check
    W->>P: vetted request
    P-->>V: proposed QuerySpec (JSON)
    alt off-allowlist
        V-->>L: record "denied (spec_rejected)"
        V-->>R: refusal (no execution)
    else valid
        V->>E: validated QuerySpec
        E->>G: aggregate + counts
        G->>L: record decision + findings
        G-->>R: released / redacted / denied
    end
```

## Data model

Four synthetic source tables; two read-only views are the only query surface.
Identifiers, free text and timestamps are **absent from the views by
construction**.

```mermaid
erDiagram
    donors ||--o{ events : donor_id
    donors ||--|| survey : donor_id
    apps   ||--o{ events : app_id

    donors  { string donor_id "DI (never exposed)" }
    apps    { string app_id "R" }
    events  { float amount_chf "S" }
    survey  { int pgsi_score "S" }
```

- **view `spend`** — `events ⨝ donors ⨝ apps`, exposing dimensions
  (`age_band, sex, canton, income_band, device_os, genre, contains_lootboxes,
  price_tier, event_type, age_rating`) and measures (`amount_chf,
  ingame_currency`).
- **view `wellbeing`** — `survey ⨝ donors`, exposing dimensions
  (`age_band, sex, canton, income_band, device_os, wave`) and measures
  (`pgsi_score, igds_score, wemwbs_score, monthly_spend_selfreport`).

See [`safetre/schema.py`](../safetre/schema.py) for column roles (DI / QI / S / R)
and [`safetre/query.py`](../safetre/query.py) for the catalogue the validator
enforces.

## Two execution paths

| Path | Trigger | Executor | Status |
|---|---|---|---|
| **Secure (default)** | web interface, in-catalogue queries | validated QuerySpec → DuckDB | Phase 1, shipped |
| **Escalation (legacy)** | analyses the DSL can't express | human-authored, reviewed code (`safetre/analyst.py` + `guards.py`) | manual; sandbox is illustrative only |

The secure path runs with no code execution at all. The legacy "LLM writes
pandas" path is retained for the red-team narrative and as the model for a
future human-reviewed escalation queue — it is **not** wired into the web
interface. See [Security model](security.md).
