---
id: D5
title: What to do about the response-time channel
date: 2026-07-26
status: accepted
question: >
  Query latency tracks cohort size closely enough to put sub-threshold cells
  in size order within a session's query budget. Should responses be padded to
  a constant time, quantised to a coarse bucket, or documented and left?
clauses: [R3, R5, R6, R18]
evidence:
  - artifacts/timing_channel_standin.json
  - artifacts/timing_channel_external.json
  - artifacts/timing_channel_web_unpadded.json
  - artifacts/timing_channel_padded.json
revisit_when: >
  Quantisation attenuates rather than eliminates, and the residual is written
  below: a patient attacker across sessions can still order some pairs at
  26-70 samples. Revisit if cross-session accounting arrives (roadmap item 4)
  and makes that bound meaningful rather than notional; if a deployment
  reports the ceiling refusing legitimate work, which would mean the quantum
  and ceiling need re-fitting to a larger dataset; or if anyone wants the
  channel closed rather than narrowed, which needs constant time — available
  today by setting the quantum equal to the ceiling, at the cost of every
  query paying it.
---

**Status: accepted 2026-07-26 — quantise with a ceiling.** Implemented as
middleware at the deployment boundary (spec R18, `response_quantum_ms` and
`response_ceiling_ms`).

## What was measured

`scripts/measure_timing_channel.py`, over the demo dataset, timing the full
service path per cohort with warm-ups discarded:

- latency tracks cohort size at Spearman **+0.86** (stand-in) and **+0.90**
  (with an external checker);
- for cells at or above the frequency threshold this reveals nothing — the
  donor marginals publish those counts already, so timing only reproduces
  public information;
- for **sub-threshold** cohorts, whose counts are published as `null`
  precisely to hide them, **9 of 15 pairs can be ordered by size within the
  20-query session budget**, several within 2–4 queries, at true gaps of 2
  donors.

Ordering suppressed cells by size is what suppression exists to prevent, so
the channel is real rather than theoretical — the security model's previous
claim that it was "sub-millisecond and swamped by jitter" has been corrected.

Two qualifications matter for weighing the options. The measurement is at the
**service boundary**, with no network in the path; a deployment adds jitter of
an unmeasured size, though an attacker on the same tailnet sees little of it.
And the external checker does **not** worsen it — latency roughly doubles and
noise rises proportionally, giving 7 of 15 pairs rather than 9 — so this is
the engine's own work leaking, not the checker's.

## Options

1. **Constant response time.** Pad every response to a fixed *T*. It closes
   the channel, and it must also *refuse* anything that would exceed *T*,
   because an overflow leaks by itself — so *T* becomes a compute budget
   alongside the existing row and memory caps, which is a coherent place for
   it to live. The cost is that every query pays the worst case, and under
   concurrency a fixed *T* is not actually constant without care.
2. **Quantise to a coarse bucket**, with a hard ceiling. Cheaper: a query
   costs at most one bucket of padding rather than the worst case. It narrows
   the channel rather than closing it — an attacker still learns the bucket —
   but the bucket can be chosen against the measurement so that sub-threshold
   cohorts land in the same one.
3. **Document and leave it.** Defensible only alongside the mitigations that
   already exist and are not nothing: the analyst is authenticated, every
   query is audited, and the session budget caps how much averaging they can
   do. It is also the option the DP accountant eventually makes moot.

## Criteria, if an option is taken

Whichever is chosen, the same measurement decides whether it worked:
**sub-threshold pairs orderable within the session budget must fall to zero**,
measured with the same script, and the cost must be stated — median added
latency, and how many previously-answerable queries the ceiling now refuses.

A defence that merely raises the number of samples needed from 3 to 15 has not
closed anything; it has bought a smaller budget's worth of protection, which
the budget already provides.

---

## What was built, and what it achieved

Quantisation, not constant time, for the reason the measurement made clear:
the differences worth hiding are small. Cells at or above the threshold have
their counts published, so collapsing *their* latency differences buys
nothing; what must be indistinguishable is the sub-threshold work, and that
varies by a few milliseconds. A 50 ms quantum puts all of it in one bucket at
a fraction of the cost of padding every request to the worst case.

Three things make the implementation match the argument. It sits in the
**outermost** middleware, so the channel rejection, the identity gate and
template rendering all happen inside the window — a fast-fail path that
skipped it would become the channel. It pads to the next boundary measured
**from arrival**, not by adding a fixed pause, which would shift the
distribution without collapsing it. And the ceiling **refuses** rather than
merely warning, with the refusal padded like everything else, because an
unpadded refusal is the fast answer that means "your query was expensive".

Measured at the same boundary, 12 samples per cohort:

| | sub-threshold pairs orderable within the budget | fewest samples | Spearman |
|---|---|---|---|
| service call, no padding | 9 of 15 | 2 | +0.86 |
| web boundary, padding off | 7 of 15 | 6 (a **1-donor** gap) | — |
| web boundary, padding on | **0 of 15** | 26 | +0.30 |

The criterion set in advance was that the orderable count reach zero. It does.

## The residual, stated plainly

Quantisation attenuates; it does not eliminate. What it leaves is a
bucket-crossing probability: two cohorts whose work differs slightly cross the
boundary at slightly different rates, so with enough samples the ordering
returns — 26 for the closest pair here, 70 for the furthest. That is above the
20-query session budget, which is what the criterion asked for, but the budget
is a per-session bound and this project does not defend across sessions. A
patient attacker opening fresh sessions is not stopped by it.

Closing the channel rather than narrowing it needs constant time, and the
implementation already expresses that: set the quantum equal to the ceiling
and every response takes exactly one bucket. It was not made the default
because every query would then pay the ceiling, and the measured exposure did
not justify that. An operator who disagrees can have it with one setting,
which is the point of putting the policy in a dial rather than in the code.
