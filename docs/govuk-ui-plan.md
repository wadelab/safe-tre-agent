# GOV.UK UI plan

Restyle the web interface to follow the
[GOV.UK design principles](https://www.gov.uk/guidance/government-design-principles)
and, for the concrete visual and interaction language, the
[GOV.UK Design System](https://design-system.service.gov.uk/). Presentation
only: no endpoint, template-contract, or security change. The target users are
TRE operators and research-infrastructure reviewers, for whom GOV.UK idiom
reads as "this is how UK public-sector services look when they are done
properly" — the right register for a DARE UK / SATRE audience.

## What "conformant" can mean here (legal constraints)

Two assets in the design system are restricted and stay out:

- **GDS Transport** (the typeface) is licensed for use on gov.uk domains and by
  government services only. We use the system's own fallback stack
  (Arial/Helvetica) instead.
- **The crown and GOV.UK header branding** are Crown copyright and reserved for
  government services. We use an unbranded header carrying only the service
  name.

Everything else — the layout grid, colour palette, type scale, focus states,
and component patterns — is published openly (govuk-frontend is MIT), so the
interface can be design-system-faithful without impersonating GOV.UK.

## Approach: hand-rolled subset, not vendored framework

Two options considered:

- **A. Vendor `govuk-frontend` dist** (MIT). Pixel-perfect and
  accessibility-tested upstream, but ships ~120 KB of CSS for one page, its
  `@font-face` rules point at font files we must not ship (console 404s or a
  Sass build step to strip them), and it buries our markup in framework
  classes.
- **B. Hand-roll a faithful subset** (~800 lines) from the design system's
  published tokens and component specs, covering only the components this one
  page uses. Matches the repo's ethos — every shipped line auditable, no build
  step, no dependency — and we already maintain a custom component (the
  pipeline) that no framework provides.

**Recommendation: B**, with the design system's exact published values
(colours, type scale, spacing scale, focus-state spec) so the result is
verifiably faithful, and an automated accessibility check (below) standing in
for the upstream test coverage we forgo.

## Visual language (tokens)

From the design system palette and type scale:

- **Colours** — text `#0b0c0c`; secondary text `#505a5f`; page `#ffffff`;
  panel/background grey `#f3f2f1`; borders `#b1b4b6`; links `#1d70b8` (hover
  `#003078`); primary button green `#00703c`; error/danger red `#d4351c`;
  focus yellow `#ffdd00`. Status tags use the design-system tag tints (green,
  red, yellow, grey, blue).
- **Type** — Arial/Helvetica stack; body 19px (16px small screens), headings
  at the GOV.UK scale (XL 48 / L 36 / M 24 / S 19, bold); sentence case
  everywhere; running text capped near 66 characters.
- **Layout** — 960px width container, two-thirds main column and one-third
  sidebar; the GOV.UK spacing scale (multiples of 5px); no shadows, no
  gradients, no glass, no rounded-corner language (GOV.UK is square).
- **Focus** — the yellow-and-black double indicator from the focus-state
  spec, on every interactive element.
- **Motion** — none. The aurora, gridlines, radar beacon, scanner sweep, glow
  pulses, and entry animations all go. State changes are instant.

## Component mapping

| Current (dark console) | Becomes (GOV.UK idiom) |
|---|---|
| Gradient title + hex SVG mark | Unbranded black header bar with the service name in white; no logo |
| — | **Phase banner**: `ALPHA` tag + "This is a research prototype running on synthetic data" |
| Identity chip (avatar, glow) | "Signed in as `user`" in the header area, with a green `Safe People` tag (red `Not allowlisted`) |
| Glass query panel | Plain form on white: `h1`, label, hint text, textarea |
| `0 / 500` counter | **Character count** component (announces remaining characters, `aria-live`) |
| Gradient "Run query" button | Green primary button, square, with the darker bottom edge |
| Example chips (mono pills) | "Example queries" as a details component containing plain link-styled buttons |
| Pipeline strip (glow dots, scanner) | Flat numbered step list; each stage gets a **text** status tag (`done` green / `stopped` red / `checking` amber / `not run` grey) so state never relies on colour alone; no animation |
| Result card (glass, accent stripe) | **Notification banner**: green success (released), blue (escalated for review); denial rendered as an **error-summary**-style banner with the reason |
| REDACTED badge | Blue notification banner + **warning text** ("Some cells were suppressed to protect confidentiality") |
| Latency / budget chips | One-line metadata under the banner ("Completed in 44ms · 19 queries remaining") |
| Findings (tinted cards) | Warning text (medium) or items in the denial's error summary (high) |
| Table with teal value bars | Plain **govuk-table**: numeric columns right-aligned, tabular figures, no bars |
| `n/a` hatched cells | `[c]` with a footnote "— [c] suppressed or not computable", the ONS convention |
| Spec / trace details (terminal look) | **Details** components ("View the validated query", "View the pipeline trace") |
| Side rail (glass, glow tags) | One-third column: dataset **summary lists**; column roles as tags (`QI` yellow, `S` red, `R` grey) |
| Codebook tooltips (`title=`) | Per-dataset details listing each column's description and value domain — tooltips are keyboard- and touch-inaccessible, so this is a required accessibility fix, not a style choice |
| Footer chips | Standard grey footer with the control statements as plain meta text |
| Dark theme | Retired. GOV.UK is light-only; a second theme doubles the accessibility surface for no conformance gain. The dark console survives in git history and the decks. |

## Behaviour (app.js) changes

Keep: the fetch flow, `#q=` hash prefill, Ctrl/Cmd+Enter submit, pipeline
final-state derivation from `data-stages`/`data-status`, suppressed-cell
relabelling. Remove: the scanner interval, all decoration. Add:

- the result container becomes `role="status" aria-live="polite"` so screen
  readers announce released/denied outcomes when the HTML swaps in;
- character-count behaviour per the design-system component (remaining-count
  message, warning state under a threshold);
- during a run the button gets `aria-disabled` semantics and the pipeline
  stages show a text `checking` tag rather than an animation.

## Accessibility work (WCAG 2.2 AA — the GDS bar)

- Landmarks: `header`, `main`, `nav` (sidebar), `footer`; a **skip link** as
  first focusable element; one `h1`; heading order without gaps.
- Every form control labelled; hint text attached via `aria-describedby`.
- No information conveyed by colour alone (pipeline tags, status banners all
  carry text).
- Contrast at 4.5:1 minimum — the GOV.UK palette meets this by construction.
- Visible focus on everything interactive; touch targets ≥ 24px.
- No `title`-attribute-only content (the codebook fix above).
- Verification: run **pa11y** (headless Chrome; its injected runner is not
  blocked by our CSP because it evaluates over the DevTools protocol) against
  the dev server for all four states — home, released, redacted, denied — plus
  a manual keyboard-only pass.

## What must not change

- The **CSP** (`script-src 'self'; style-src 'self'`), no inline styles, no
  CDNs, no webfonts — all GOV.UK styling is self-hosted CSS.
- The server contract the tests pin: `status-released|redacted|denied`
  classes, no `<table>` on a denial, no `style="` in responses, spec/trace
  content.
- Endpoints, templates' context variables, and everything in
  [the specification](specification.md) — this is presentation only; every
  R/P clause is untouched.

## Delivery

1. **Commit 1** — stylesheet + template + JS rewrite (the mapping above), all
   tests green.
2. **Commit 2** — pa11y/keyboard findings fixed; small test additions (skip
   link present, `aria-live` on the result region, no `title`-only codebook).
3. **Commit 3** — refresh `docs/figures/web-ui-home.png`, note the restyle in
   the user guide, retire dark-theme references.

Roughly: `app.css` rewritten (~800 lines), `index.html` restructured,
`_result.html` adjusted, `app.js` −80/+60 lines.

## Decisions to confirm

1. **Pipeline strip** — keep as a flat, text-tagged step list *(recommended:
   it is the demo's storytelling)*, or drop it and rely on the trace details?
2. **Dark theme** — retire *(recommended)*, or keep behind a toggle at the
   cost of double accessibility testing?
3. **Value bars** — drop from tables *(recommended: not a GOV.UK pattern)*,
   or keep as a thin, single-hue variant?
4. **Approach** — hand-rolled subset *(recommended)*, or vendor
   `govuk-frontend`?
5. **Phase banner** — `ALPHA` with "research prototype, synthetic data"
   wording?
6. **Service name** — the header needs one in plain sentence case; suggest
   "Safe outputs gateway" with the h1 "Run a safe aggregate query".

## Principles, mapped

Where each GDS principle bites in this plan: *start with user needs* (the
analyst needs valid filter vocabulary — the codebook moves out of tooltips);
*do less* (drop the decoration, the bars, the second theme); *design with
data* (keep latency/budget as plain metadata); *do the hard work to make it
simple* (suppression explained in a sentence, `[c]` footnote); *this is for
everyone* (the WCAG 2.2 AA list above); *be consistent, not uniform*
(design-system components, unbranded); *make things open* (this plan, and the
hand-rolled CSS, are in the repo).
