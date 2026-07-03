# Tool manifest and two-LLM workflow

The intended production shape has two LLM-facing layers:

- **outside LLM**: user-facing planner, possibly a frontier model, outside the
  safepod;
- **inside LLM**: optional safepod-side reviewer/helper for statistical
  appropriateness and policy interpretation.

Neither LLM is the security boundary. Both are constrained by a signed,
versioned tool manifest and deterministic safepod validation.

## Workflow

```mermaid
sequenceDiagram
    autonumber
    actor R as Researcher
    participant O as Outside interface + LLM
    participant M as Public manifest
    participant S as Safepod validator
    participant I as Inside LLM reviewer
    participant T as Fixed stats tools
    participant G as Disclosure gateway

    O->>M: fetch manifest + hash
    R->>O: natural-language analysis request
    O-->>S: proposed tool call + manifest hash
    S->>S: deterministic schema/policy validation
    opt borderline method or policy question
        S->>I: request review over spec + manifest, no raw rows
        I-->>S: advisory finding
    end
    S->>T: execute fixed tool if allowed
    T-->>G: aggregate/model output + disclosure metadata
    G-->>R: released, redacted, or denied output
```

## Public manifest

The outside LLM needs to know what is available, but not anything row-level. The
public manifest is safe to show outside the safepod and contains:

- manifest version and SHA-256 hash;
- available tool IDs and request schemas;
- allowlisted datasets, dimensions, and measures;
- coarse constraints such as max filters and max group-by fields;
- release expectations such as minimum cell size and count rounding;
- planned tool classes clearly marked as **not executable**.

The current endpoint is:

```text
GET /api/manifest
```

It currently publishes only one executable tool: `aggregate_query`. That tool
supports fixed count, mean, sum, and Pearson correlation requests. Correlation
uses two validated measure columns from one dataset and returns only aggregate
`value`, `p_value`, and `n`.

Some fixed tools may use internal analysis variables, such as raw age for
donor-level age/spend correlation. These variables are not public grouping or
output columns. They are accepted only in the specific schema positions the
safepod validator allows.

Planned stats families such as `glm`, `anova`, and `regression` are listed as
planned only. A proposed tool call is executable only if it appears in `tools[]`
with `status: "available"`.

## Inside vetting

The inside LLM can be useful, but only as an adviser. It can review questions
like:

- is a GLM family appropriate for this outcome?
- is the requested contrast interpretable?
- does the formula look like a fishing expedition?
- should this be escalated to human review?
- does the explanation to the researcher make sense?

It must not be allowed to:

- waive deterministic validation;
- lower disclosure thresholds;
- execute code;
- inspect raw rows;
- approve a tool absent from the enforcement manifest;
- return values not produced by a fixed tool and disclosure gateway.

The inside LLM's output should become an audit finding, not an authorization
decision.

## Future stats tools

Standard analyses should enter as fixed-function tools with explicit schemas,
not as arbitrary code. Examples:

| Tool class | Typical use | Key vetting constraints |
|---|---|---|
| `glm` | logistic, Poisson, Gaussian, gamma-style models | allowed outcome/predictor roles, min events per parameter, no rare levels, no row diagnostics |
| `regression` | OLS/robust linear models | min rows per parameter, bounded covariate count, no residual/fitted-value release |
| `anova` | group comparisons and contrasts | min group size, predeclared contrasts, suppress sparse levels |
| `survival` | time-to-event models | extra caution: event counts, censoring patterns, and time granularity can disclose |

Every stats tool should define:

- request schema;
- allowed datasets and variables;
- parameter limits;
- minimum cohort and per-level counts;
- model diagnostics that may be released;
- model diagnostics that must never be released;
- disclosure checks for coefficients, contrasts, p-values, CIs, residuals, and
  influence measures;
- audit fields and manifest version.

## Regression outputs are disclosure outputs

Model outputs can leak. A coefficient for a rare category, a separated logistic
model, a very narrow confidence interval over a tiny group, or a suppressed
level implied by a contrast can all disclose information. Treat model summaries
like aggregate tables: they need minimum support, dominance/influence checks,
rounding, suppression, lineage tracking, and sometimes denial.

## Update discipline

The manifest is part of the safepod contract. Do not auto-update it inside a
real safepod. A new tool or changed manifest requires the same process as a code
update: security review, tests, signed/pinned artifact, deployment approval, and
audit trail.
