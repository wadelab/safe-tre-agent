---
id: D11
title: A progress indicator may report the clock, never the work
date: 2026-08-19
status: accepted
question: >
  A multi-step analysis behind one HTTP request leaves the analyst watching
  nothing for as long as it runs, and the inside analyst's loop is the worst
  case. Should the interface report progress, and if so what may it report —
  the pipeline stages as they complete, the analyst loop's step count, or
  something narrower?
clauses: [R9, R11, R18]
evidence:
  - docs/decisions/D5-timing-channel.md
  - safetre_web/timing.py
  - safetre_web/static/app.js
  - tests/test_progress_indicator.py
  - artifacts/timing_channel_web_unpadded.json
revisit_when: >
  Someone wants the indicator to reflect actual progress rather than elapsed
  time — which needs a server-sent event per step, a new channel, and a new
  normative clause, because the argument below turns entirely on the server
  sending nothing between the request and the quantised response. Also revisit
  if asynchronous delivery arrives (D5's preferred future for the timing
  channel): a job-handle design changes the shape of this question, because
  the poll interval becomes the client's choice rather than the work's.
---

**Status: accepted 2026-08-19 — the indicator is client-side and reports
elapsed time against the published ceiling. The server sends nothing new.**

## The decision

The interface may show that work is happening and how long it has been
happening. It may not show how far along the work is, because how far along the
work is, is a fact about the data.

Concretely: a readout driven by the browser's own clock, calibrated to the
`response_ceiling_ms` the manifest now publishes, behaving identically for every
request. No server-sent progress events, no per-stage completion, no step
counter, and no change to when the response arrives.

## Why the obvious version is a disclosure

The obvious progress indicator advances a pipeline step as each one completes.
Three separate things leak, and only the first is easy to see.

**Content.** A step that reports its own outcome — released, denied, retrying,
suppressed — is reporting the gateway's verdict on the cohort. That is the
count-class fact `service.WITHHELD_MESSAGE` exists to refuse, and it is the same
disclosure as [hardening #109](../hardening-log.md), which put the same fact in
a published research record by a different route. What the analyst may see at
the end is one canonical refusal per step; a live indicator may not say more
than the final answer will.

**Count.** For a fixed, request-declared program — a locked plan's stages — the
number of steps is the analyst's own and safe. For the inside analyst it is not:
the loop stops when it has concluded, and when it has concluded depends on what
it saw. An indicator that converges on the true step count reports a data-derived
number. **This is why a genuine progress bar cannot be made safe for a
variable-length process**: "fraction complete" has no request-decided
denominator.

**Timing.** The one that would break something already working.
[D5](D5-timing-channel.md) measured latency tracking cohort size at Spearman
+0.86, and +0.90 with an external checker — close enough to put sub-threshold
cohorts in size order within a session's budget. R18 closed that by quantising
every response and enforcing a ceiling as a deadline, and
`safetre_web/timing.py` says how: *"The response is buffered rather than
streamed."* The buffering is the control. A streamed progress event escapes it,
because an event emitted when a stage finishes is an unpadded timestamp of that
stage's work. Streaming per-stage progress would hand an attacker one timing
sample **per stage** where R18 leaves them one per request — strictly worse than
the channel D5 spent a round narrowing, and it would pass every existing test,
because nothing tests the timing of something the app does not currently send.

## Why the client-side version discloses nothing

The browser already holds everything the indicator needs. It knows when it sent
the request, because it sent it; `app.js` has read `performance.now()` at
submission since the pipeline display was written, and already reports
`Completed in …ms` from it. The ceiling is a policy constant, request-independent
and already documented; publishing it in the manifest is R9's business and sits
beside `minimum_cell_size`, which is a far more sensitive dial.

So the indicator is a rendering of two numbers the client already has. It adds no
server behaviour, no new response, and no new timing. That is the whole argument,
and it is why this needs no new clause: the design's claim is that it changes
nothing the specification governs, and `tests/test_progress_indicator.py` pins
exactly that — the manifest carries the dials, no response is streamed, and the
front end contains no `EventSource`, no streaming reader, and no progress route.

## The inside analyst's path has no ceiling, and the indicator must not claim one

`/api/chimp` is in `DEADLINE_EXEMPT` (`safetre_web/timing.py`): the boundary
returns before padding or racing it, because a multi-step analysis legitimately
takes far longer than the per-query ceiling and racing it would refuse every real
research question. So on that path there is no ceiling to count toward, and the
indicator carries no `data-ceiling-ms` — it shows bare elapsed time. Telling an
analyst they are 3 seconds into a 5-second ceiling that does not apply to them
would be a smaller failure than a disclosure and still a failure.

That path's latency is therefore unpadded, which is a pre-existing accepted
limit rather than anything this decision introduces: `timing.py` states it, and
states why — the timing reveals how many analyses the loop ran, not any withheld
cell value, because the dossier carries only vetted releases. The indicator does
not widen it. An analyst waiting for their own request already holds a clock;
rendering the number they could read off the wall is not a new channel, and that
is the same argument as for the padded path, just with a weaker starting point.

## What this costs

The indicator is honest but not informative: it tells an analyst that the system
is working and roughly how long is left before the ceiling refuses, and it cannot
tell them which stage is slow or how much remains. For a three-minute inside
analyst run that is a real loss of interface quality, accepted deliberately.

It also means the indicator is slightly *dishonest in the safe direction*: it
advances at the same rate whatever the query is doing, so a fast query shows the
same first second as a slow one. Labelled as elapsed time rather than progress,
which is what it is.

## What was considered and rejected

**Server-sent events, one per pipeline stage.** The natural implementation, and
the timing channel above. Rejected.

**Advance the existing step tags during the wait.** They are set to "Checking"
together at submission and resolved together from the server's public trace,
which `service._public_trace` has already stripped for data-derived refusals.
Advancing them individually would mean advancing them on completion, which is the
same channel in a smaller costume. Kept as it is, and pinned.

**A progress bar over the analyst loop's `max_steps`.** `max_steps` is
request-decided, so the denominator is safe — but the numerator is not, and a bar
that stops at 3/8 has published that the analyst concluded after three steps.
Rejected; a bar filling toward the ceiling on the clock is the safe cousin and is
what was built.
