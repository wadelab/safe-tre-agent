---
id: D5
title: What to do about the response-time channel
date: 2026-07-26
status: open
question: >
  Query latency tracks cohort size closely enough to put sub-threshold cells
  in size order within a session's query budget. Should responses be padded to
  a constant time, quantised to a coarse bucket, or documented and left?
clauses: [R3, R5, R6]
evidence:
  - artifacts/timing_channel_standin.json
  - artifacts/timing_channel_external.json
revisit_when: >
  Open. The measurement exists and the options are costed below; what is
  missing is a judgement about how much usability to spend on a channel that
  needs an authenticated, audited analyst spending their query budget to
  exploit. Two things would settle it in one direction or the other: an
  end-to-end measurement over the real restricted channel, which would say how
  much of the signal survives network jitter, and the DP accountant, which
  closes this channel along with the rest of the release-decision oracle.
---

**Status: open.** The measurement is done; the response is not chosen.

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
