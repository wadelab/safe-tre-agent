# Model runtime

The model is a replaceable planner, not the security boundary. The secure path
only requires a component with this interface:

```python
complete(system: str, user: str) -> str
```

The default real adapter calls a local OpenAI-compatible
`/v1/chat/completions` endpoint. That keeps the runtime swappable across vLLM,
llama.cpp server, Ollama-compatible proxies, or a site-specific adapter.

## Capability assumption

Design for a future local model that is strong enough to reliably translate
research requests into `QuerySpec` JSON. A useful planning target is a good
120B-class model: think two Spark-class NVIDIA test systems for development and
an H100-class or similar accelerator profile for production.

Do not make safety depend on that capability. Even a strong local model is still
untrusted:

- it cannot execute code;
- it cannot write SQL;
- it cannot query raw rows;
- it cannot name identifiers or free text unless the validator allows them;
- its proposal is rejected unless it is a valid `QuerySpec`.

## Profiles

| Profile | Purpose | Expected endpoint |
|---|---|---|
| `mock` | offline tests, demos, red-team determinism | no model server |
| `local-test` | development on smaller local GPU systems | `http://127.0.0.1:8000/v1` or another in-pod host |
| `local-prod` | safepod production with stronger accelerator capacity | loopback or fixed safepod model host |
| `remote-dev` | synthetic-data experiments only | explicitly enabled remote HTTPS endpoint |

Production should use `local-prod`. `remote-dev` is never acceptable for real
data because the research question itself can be sensitive egress.

## Configuration

```bash
SAFETRE_LLM=real
SAFETRE_LLM_BASE_URL=http://127.0.0.1:8000/v1
SAFETRE_LLM_API_KEY=local
SAFETRE_LLM_MODEL=local-120b
SAFETRE_LLM_TEMPERATURE=0
SAFETRE_ALLOWED_LLM_HOSTS=localhost,127.0.0.1,::1
```

By default, the client rejects non-allowlisted LLM hosts. If the model server is
a separate machine inside the safepod, add that fixed hostname or IP to
`SAFETRE_ALLOWED_LLM_HOSTS`.

For synthetic-data development only:

```bash
SAFETRE_ALLOW_REMOTE_LLM=1
SAFETRE_LLM_BASE_URL=https://example-llm-provider.invalid/v1
```

A hosted OpenAI-compatible endpoint works the same way — set the base URL,
key and model id, with the same explicit opt-in. Remote endpoints are egress
channels and must stay synthetic-data-only:

```bash
export SAFETRE_LLM=real
export SAFETRE_ALLOW_REMOTE_LLM=1
export SAFETRE_LLM_BASE_URL=https://<provider>/v1
export SAFETRE_LLM_API_KEY=...
export SAFETRE_LLM_MODEL=<model-id>
```

This documentation deliberately does not name the provider or model used for
the maintainers' own demos: advertising which model plans queries invites
model-targeted prompt injection, and no safety property depends on the choice —
the planner is untrusted whichever model fills the role.

Legacy `OPENAI_BASE_URL`, `OPENAI_API_KEY`, and `SAFETRE_MODEL` are still read as
fallbacks, but new deployments should use the `SAFETRE_LLM_*` names.

## Replacement rule

If a future runtime is not OpenAI-compatible, add a small adapter that implements
`complete(system, user)`. Do not change the planner, validator, engine, or
disclosure gateway to suit a model runtime. The runtime is replaceable; the
security boundary is not.
