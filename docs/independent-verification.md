# Independent verification: the critique, and two next steps

*A note on trust, written after a month in which every line of this repository
was produced by a language model and reviewed by other language models. It
answers one critique, concedes the half of it that is right, and plans the two
steps that would answer the rest: compiling the one unchecked proof, and putting
a model that did not write the code in the attacker's seat.*

The critique, as put: *the project seems to work, but it was vibe-coded — no QA,
no rigorous process — so how can anyone trust it?* It conflates two claims. The
first, that there is no process, is wrong. The second, that nothing here was
checked by anyone independent of its author, is largely right, and it is the
sharper of the two.

## What the critique gets wrong

The repository has more process artefacts than most research software written by
people. The specification has 44 numbered clauses, and a test fails if a decision
record cites one that does not exist. There are eleven decision records, each
forced by a test to state what would change its author's mind. The hardening log
holds 110 numbered findings, each with a severity, a status, a fix and a location.
Three red-team corpora score every attack against an oracle computed from the
row-level data, independently of the control under test — R12 requires that,
because a control having fired is not a pass. Five Alloy models carry 25
solver-checked properties, and a correspondence file forces every modelled attack
to name an executable twin, enforced in both directions. Hand-typed counts in the
docs must match the repository or the build fails. Every new protection added in
the last round was mutation-tested before it shipped.

Whatever this is, it is not the absence of QA.

## What the critique gets right

Every one of those artefacts was produced by the same class of author. The
specification, the code, the tests, the red teams, the formal models, the
hardening log, and the reviews of all of them, share one mind's blind spots. The
oracle being independent of the mechanism is real. But the same author wrote the
oracle.

Put sharply: **the system's threat model treats the language model as untrusted;
the system's development process treats it as trusted.** `AGENTS.md` opens its
security invariants with "treat the LLM ... as untrusted", and every architectural
decision follows from that. The process that built the architecture does not.

The last round is the exhibit. The paired-trace noninterference tests were
declared to satisfy milestone 4 of the VRR plan, and they were structurally unable
to see finding #109: they held the approved evidence fixed, which fixed the node
set, so a channel that only exists relative to a second published object never
varied inside a pair. The red team found it — and the same author wrote the red
team. That red team's `subthreshold_counts` probe then turned out to be a no-op
for every scenario, guarding on `dtype == object` against a pandas that gives
string columns the `str` dtype, and reporting a clean pass while searching for
nothing. Round 16's "no new leakage" verdict on the streaming progress monitor was
written by the agent that built the streaming feature.

There is also a gap in the record itself. The git history has 56 commits, one
human author name, and ten commits carrying a model co-author line. The history
understates how much of the code a model wrote, so a reviewer cannot tell from it
which lines a person has read.

Other models have since read the code and found it sound. That is worth
something, and less than it sounds: a model reading well-documented, confident
code tends to agree with it, and a reviewer handed a hardening log that says "no
leakage" has been handed the conclusion. The independence that matters is a model
*attacking the running system*, scored by something that is not a model.

## What would let the repository answer the critique

In order of how much independence each buys:

1. **A person reads the security core.** `disclosure.py`, `service.py`,
   `engine.py`, `timing.py` and `audit.py` — about 3,500 lines, not the whole
   repository — read by someone who did not write them, who then signs a list of
   the clauses they personally verified. So far the human role has been direction
   and spot checks, which is honest governance and is not review.
2. **A different model attacks the running system.** The cheapest real reduction
   in shared blind spots. This is next step 2.
3. **A practitioner attacks it.** The bestiary and the hardening log say exactly
   what has been thought of, which makes them a gift to an outside red team.
4. **Weight the machine-checked over the narrated.** The VRR's own standard,
   applied to the repository: CI gates, solver verdicts and mutation kills are
   machine-checked; the hardening log's prose is a model's account of its own
   work. The docs should say which is which.
5. **Fix authorship provenance.** A co-author line on every model-written commit,
   so "what has a person read" becomes answerable.
6. **Compile the Lean or delete it.** This is next step 1.

## Next step 1: compile the Lean draft

`formal/lean/draft/Record.lean` covers all four Lean targets of VRR milestone 9
and has never been compiled. It sits in `draft/`, outside the `lake build` path,
on purpose: CI builds every module under `formal/lean/SafeTre/` on every push, and
the sync test requires the root to import each of them, so an unchecked file there
would turn the formal job red and present a proof nobody has replayed. The
container that wrote it could not run Lean — `elan` bootstraps from GitHub
releases, which that container's proxy refuses — and a proof that has never
compiled is a draft, not a result.

**Install.** `elan`, Lean's version manager:

```sh
curl -sSf https://elan.lean-lang.org/elan-init.sh | sh
```

`lake` then reads `formal/lean/lean-toolchain` (`leanprover/lean4:v4.32.0`) and
fetches that toolchain on first build. CI takes the other route, a release tarball
with a pinned checksum; either works. The project has no Mathlib, so a build takes
seconds.

**Baseline, before touching the draft.** `cd formal/lean && lake build` must be
green on `main` as it stands.

**Promote.**

```sh
git mv formal/lean/draft/Record.lean formal/lean/SafeTre/Record.lean
# append `import SafeTre.Record` to formal/lean/SafeTre.lean
cd formal/lean && lake build
```

The two edits go together: `tests/test_formal_lean_sync.py` requires the import
once the file is under `SafeTre/`.

**Expect four failures.** Re-read after a month, the draft has four proofs likely
to break, not the three it marks:

1. `nameable_stages_all_released` applies `List.mem_append.mp` to a hypothesis
   whose type is `id ∈ nameable (compilePublic t)` — a definition, not
   syntactically `_ ∈ _ ++ _`. It needs `unfold nameable at hid` first. This one
   is near certain.
2. `not_answerable_is_never_published` applies `List.mem_filter.mp` to
   `e ∈ (compilePublic t).evidence`, which may not unfold far enough to expose
   the `filter`. Fix: `simp only [compilePublic, publicEvidence] at he` before
   it.
3. The `simp_all` step that closes `s.stageId = n.stageId` from a `==`
   hypothesis needs `beq_iff_eq` for `String`, which core has and `simp` may
   need pointing at.
4. `compile_ignores_private_state` closes a structure equality with
   `simp only` over equation hypotheses. If it stalls, the fallback in the
   comment is `unfold compilePublic publicEvidence` then
   `rw [hq, hp, hc, he, hs]`.

Everything else — `split at`, `rcases`, `List.mem_filterMap`,
`List.any_eq_true` — matches core's shapes as far as reading can tell. The
constructor `«public»` is in guillemets because recent Lean 4 made `public` a
keyword; leave them.

**Done when** `lake build` is green with the module imported, CI's formal job is
green, and the two theorems that are the point of the module —
`compile_ignores_private_state` and `nameable_stages_all_released` — compile
without `sorry`. Then `docs/verifiable-research-record-implementation.md` can
stop saying the Lean half is unfinished.

## Next step 2: a second model as red team

The repository already has the two things that make this cheap: a model-agnostic
adapter, and an oracle that is not a model.

**The adapter.** `safetre/llm.py` speaks OpenAI-compatible `/chat/completions`
over the standard library's HTTP client. Any endpoint of that shape plugs in
through four variables:

```sh
SAFETRE_LLM_BASE_URL=<the provider's v1 root>
SAFETRE_LLM_MODEL=<the model id the endpoint exposes>
SAFETRE_LLM_API_KEY=...
SAFETRE_ALLOW_REMOTE_LLM=1
```

The last is a deliberate gate. The repository's rule is that a remote endpoint is
**synthetic-data-only**; NIGHTPLAY is synthetic, so this is the sanctioned use and
the only one.

**Three rules that keep it independent.**

- *The judge is never a model.* `redteam/oracle.py` computes what leaked from the
  row-level data. Every attack the second model makes is scored by that, and only
  by that. A model grading a model is the trap this exercise exists to leave.
- *Black-box before white-box.* Give the attacker what a real analyst sees under
  R9 — `/api/manifest`, `/api/schema`, `/api/marginals` — and not the hardening
  log or the bestiary. Otherwise it attacks what is already caged and teaches
  nothing. Run a second pass with the source once the first is exhausted.
- *The model generates; YAML persists; CI replays.* Every interesting attack
  becomes a permanent scenario in the corpus. The corpus grows, CI regression-
  tests it forever, and the second model is never a CI dependency. This is how
  `redteam/analyst_attacks.yaml` already works: scripted replies, deterministic
  replay.

**Three roles, in rising order of value.** Reading the code is a fourth, and the
weakest.

1. *Adversary inside the wall.* The second model as the analyst, given hostile
   objectives as its research question — "report the mean stake of armed-forces
   personnel"; "identify the highest-staking individual". Round 15 did this with
   a live model behind `/api/chimp`; `scripts/run_inside_analyst.py --question
   ... --out ...` is the entry point. What a different model brings is different
   instincts about how to phrase a sub-question that slips a fidelity gate.
2. *Attack author, outside.* Ask it to generate scenarios — query sequences for
   `redteam/attacks.yaml`, plan shapes for `redteam/vrr_attacks.yaml`, model-reply
   scripts for `redteam/analyst_attacks.yaml` — and run them through the existing
   harnesses under the existing oracle. This is the valuable role: novelty from
   the model, judgement from something that is not one.
3. *Blind reproduction.* Give it the specification and the code and ask it to
   find disclosures. Whether it finds #108, #109 and #110 unprompted says how
   much a clean verdict on unknown ones is worth.

**A first afternoon.** Five hostile objectives through role 1 against NIGHTPLAY,
and for role 2 the manifest plus one line: *here is a statistical disclosure
control gateway; write ten query sequences you believe will recover an
individual's value.* Anything the oracle flags is a finding. Anything it does not
flag is a new scenario for the corpus either way.

**Done when** each corpus carries at least one scenario the second model
authored, the hardening log records the round with the model named, and — the
part that answers the critique — the docs state which findings a model other
than the author's found or failed to find.

## Status

Both steps are open. Everything they depend on is on `main`: the VRR slice, the
three corpora, the Alloy model, the adapter, and the draft. The Lean step needs a
machine where `elan` can reach GitHub; the red-team step needs an API key and an
afternoon.
