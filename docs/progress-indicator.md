# The inside-analyst progress indicator (planning)

**Status: implemented — 2026-08-20.** Supersedes the indeterminate progress bar
added ad hoc alongside the unified ask box. The "Mechanism" section below now
describes what shipped rather than what is planned; the bar has been removed.

## The problem

A **parse outside** query answers in milliseconds: the seven-box gateway-check
strip flips `Not run` → `Checking` → `Completed`/`Stopped` and the result lands.
A **parse inside** run is different — Chimp issues several sub-questions through
the gateway and a whole run takes tens of seconds to a minute. It is one blocking
`POST /api/chimp` that returns the finished dossier at the end, so during the run
the page has nothing to show but "working…". The stopgap was an indeterminate
bar with an elapsed-seconds counter. It is honest that time is passing but says
nothing about *what is happening*, and a moving bar sits awkwardly against the
UI's deliberate "no decorative motion" rule
([govuk-ui-plan.md](govuk-ui-plan.md)).

## The decision

Reuse the box language the gateway strip already uses, one box **per analysis
step**, and drive it from the server as each step resolves:

- **pending** — grey, `queued` (a step the analyst has not reached yet is not
  shown until it starts; the count is not known in advance);
- **running** — amber, `running`, while the sub-question is at the gateway;
- **released** — green, `released` (or `redacted`, yellow), when the gateway
  let a result out;
- **denied** — red, `denied`, when the gateway refused it.

You watch the dossier build: four to nine boxes appear and settle to green or
red, and the finished dossier replaces the strip when the run concludes. This is
discrete state, not animation — the same reason the strip already reads as a list
of text status tags rather than a spinner, so it keeps the "Motion — none"
principle rather than breaking it. The indeterminate bar retires.

State is always carried by **text** (`running`/`released`/`denied`), never colour
alone, and the strip is an `aria-live` region so each settled step is announced.

## Mechanism

The step outcomes are already computed server-side and already appear in the
dossier the batched endpoint returns today; the only change is to emit them **as
they happen** instead of all at once.

- `safetre/inside_analyst.py` — `AnalystLoop` grows an internal generator
  `iter_run(question)` that yields a typed event as each step completes
  (`("step", Step)`), then a final `("done", Dossier)`. The existing
  `run(question)` becomes a thin consumer of it that returns the final dossier,
  so every current caller and test is unchanged.
- `safetre_web/app.py` — a new `GET/POST /api/chimp/stream` returns a
  `text/event-stream` (Server-Sent Events). It runs the loop behind the same
  gateway, auditor and session lock as `/api/chimp`, emits one SSE message per
  `step` event (the sub-question text and the gateway verdict only), and a final
  `done` message carrying the rendered dossier HTML. `/api/chimp` stays for
  non-streaming callers and tests.
- `safetre_web/static/app.js` — parse-inside submit switches to the stream: read
  the event stream, append/settle a box per `step` event, and swap in the
  dossier HTML on `done`. A browser without `EventSource`/stream support falls
  back to the plain `/api/chimp` POST and the current end-of-run render.
- `safetre_web/templates` — a small `_chimp_steps` partial (or inline nodes)
  reusing the `.step`/`.step-status` classes the gateway strip already styles.

This is a first, thin slice of the **D5** asynchronous submit-and-collect
direction the inside analyst has always pointed at
([inside-analyst.md](inside-analyst.md)): the run still completes within one
request, but its progress is now observable rather than opaque.

## What this does not change (disclosure)

- **Only vetted results cross.** A `step` event carries the sub-question text and
  the gateway's verdict (`released`/`redacted`/`denied`) — both already present
  in the dossier `/api/chimp` returns. It never carries a suppressed value,
  Chimp's working notes, or any per-observation data. The final `done` payload is
  the same vetted dossier HTML as today.
- **The gateway is unmoved.** Every sub-question still goes through
  `service.handle` with the session auditor, differencing lineage and selection
  budget; streaming changes *when* an outcome is shown, never *whether* it is
  allowed.
- **Timing.** Streaming makes each step's completion time observable, where the
  batched response revealed only the total. `/api/chimp` is already exempt from
  the R18 response-time ceiling (a stated inside-analyst residual, D5), so
  per-step timing is a finer view of an already-accepted exemption, not a new
  class of channel — the numbers that cross still cross only in the vetted
  dossier. If the eventual D5 async design needs to close per-step timing, it
  does so there; this PoC slice inherits the existing exemption and says so.

This was red-teamed (hardening log, round 16): the stream was measured to be a
strict subset of the dossier the same run returns, with no numeric leak, no XSS
(step fields render through `textContent`), no SSE-framing injection (a jailbroken
sub-question carrying forged `event:`/`data:` lines stayed one escaped JSON
string), and no timing bit beyond the status already shown.

## Accessibility and reduced-motion

No animation is introduced. Boxes change state discretely; `prefers-reduced-motion`
needs no special case because there is nothing to animate. Each box states its
status in text, the strip is `aria-live="polite"`, and the disabled Ask button
already signals that a run is in flight.

## Scope and non-goals

- **In scope:** per-step boxes for parse-inside, driven by an SSE stream;
  retiring the indeterminate bar; a non-streaming fallback.
- **Out of scope:** the full D5 async submit-and-collect (durable job ids,
  reconnect, collect-later); per-step timing padding; any change to what the
  gateway releases or to the parse-outside path, which keeps the strip it has.
