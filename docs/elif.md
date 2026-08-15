# What we built, explained simply

*The TL;DR and the explain-it-like-I'm-five version of the GLM /
statistical-procedure-framework round (July 2026). The precise version lives
in the [specification](specification.md) and
[verifiable extensions](verifiable-extensions.md); nothing here overrides
those.*

## TL;DR

The gateway can now fit **statistical models** — gaussian, logistic and
Poisson GLMs (generalized linear models, the workhorse regressions of
applied statistics) — and it does so **without ever looking at anyone's
individual data**. A model is computed *only* from small summary tables ("cells") that
the existing disclosure gateway has already checked and released. If even one
cell of the model's table would have been blocked, the whole model is refused,
loudly. Every released model ships with the exact cell table it was computed
from, so an analyst can re-run the maths and get **bit-for-bit identical
coefficients** — which is also how we *prove* the model never used anything
secret. Around this sits a general **framework for adding statistical
procedures**: each new procedure is a registered contract whose safety
obligations are enforced by CI (the build fails if you skip one), checked by
exhaustive enumeration over its finite request space (767 model shapes),
fuzzed by property tests, attacked by a 34-scenario red-team, cross-validated
against reference implementations, and — new for this project — model-checked
by an **Alloy solver** in CI. Along the way we found and fixed a real
pre-existing bug: released counts carried the exact number right next to the
rounded one, making count rounding a no-op.

## Explain it like I'm five

### The library with a careful librarian

Imagine a library that holds everyone's diaries. You are never allowed to
read a diary. But you may ask the librarian questions about *groups*:
"how many people in Scotland wrote about football?" The librarian follows
strict rules: she never answers about groups smaller than ten people, she
rounds her answers so you can't spot one person joining or leaving, and she
remembers every question you've asked so you can't sneak up on one person by
asking two almost-identical questions and comparing.

There is also a robot helper who turns your plain-English question into the
librarian's official request form. **We do not trust the robot.** It might be
confused, or even tricked by something nasty written inside a diary. That's
fine, because the robot can't *do* anything — it can only fill in the form,
and the librarian checks every box on the form against her rulebook before
anything happens.

### What's new: the librarian can help with proper statistics now

Researchers don't just want counts and averages — they want *models*:
"does spending predict wellbeing, once you account for age?" Usually,
fitting a model means a computer reads every individual's data. That would
break the whole library rule.

Here's the trick we built on: for the models we allow, the maths has a
special property — **the model can be computed exactly from the group
summaries alone**. You don't need the diaries; you only need the same little
tables of "how many, and their average, per group" that the librarian already
knows how to check and release. We verified this to fourteen decimal places
against reference implementations: fitting on the checked summaries gives
*precisely* the same answer as fitting on the raw data would.

So when you ask for a model, the system:

1. works out which group tables the model needs;
2. asks the librarian for each one, **through exactly the same rulebook as
   always** — small groups blocked, counts rounded, questions remembered;
3. **refuses the whole model, out loud, if even one cell was blocked** — it
   never quietly merges groups or drops cells and hands you something that
   looks like an answer to your question but isn't;
4. fits the model using *only* those released tables — the fitting code is
   physically incapable of touching the database (it's a pure calculator
   that receives a table of numbers);
5. gives you the coefficients **and the very table they were computed
   from**.

That last part is the beautiful bit: because you hold the table, you can
redo the calculation yourself and get the same numbers, to the last bit.
A machine does exactly that, for every possible model, as a test. If the
model ever used anything beyond what was released to you, that test would
catch it. The safety argument isn't "trust our clever new checks" — it's
"the model literally cannot know more than the librarian already said out
loud."

### Why refusing loudly matters

A helpful-seeming system might think: "one group is too small — I'll just
quietly leave it out and answer anyway." That's dangerous, because you'd
believe you got an answer to *your* question when you actually got an answer
to a slightly different one. This system never does that. Blocked means
blocked, and it says so. (The refusal itself is careful too: it's computed
only from things you were allowed to know anyway, so a "no" can't leak a
secret either.)

### The framework: adding new statistics without new holes

The real product of this round isn't one model type — it's the **rulebook
for adding rulebook entries**. Every statistical procedure is now a
registered *contract* that must declare:

- exactly which columns it may touch (nothing secret is even expressible);
- how it compiles into the one blessed, read-only query shape;
- its safety witnesses (who could dominate this number?) — or, for models,
  proof that it inherits them by only consuming checked tables;
- exactly which columns it releases, and how each must be treated;
- its complete, finite space of possible requests, exported as data.

Skip any of these and **the build fails** — a test literally enumerates the
registered procedures and demands each obligation. Then four layers of
checking run on every change: try *every single* possible request shape
(there are exactly 767 model shapes — small enough to try them all);
bombard the pipeline with randomly generated requests; replay 34 scripted
scenarios (29 attacks, 5 benign) with the safety gateway off and on; and hand a
mathematical solver
(Alloy) a bounded model of the whole flow so it can search for *any*
sequence of events where a model gets fitted despite a blocked cell. It
finds none — and when we deliberately weaken the rule, it finds the
counterexample immediately, which is how you know the check is real.

### And one embarrassing thing we found

While planning all this, we noticed the librarian's existing counting rule
had a hole: she rounded the count in one column of her answer... and wrote
the exact count in the column right next to it. Rounding was doing nothing
for count queries. Fixed, tested, and — honestly — exactly the kind of gap
the new "declare every released column" contract exists to make impossible.

## The numbers

| What | Count |
|---|---|
| Requirement / prohibition clauses in the spec | R1–R18, P1–P22 |
| Model shapes, all machine-checked | 767 (718 GLM + 49 ANOVA) |
| Tests collected in the default suite | 1056 (plus an exhaustive `-m slow` pass) |
| Red-team scenarios, every attack blocked by a named control | 34 (29 attacks, 5 benign) |
| Solver-checked properties (Alloy, in CI) | 19, across three models |
| Coefficient agreement with reference implementations | ~1e-14 (exact maths), 1e-8 (tested bound) |
| New runtime dependencies | 0 (the fitter is stdlib-only) |

## What it still does not do

Models with continuous predictors for logistic/Poisson families (their maths
genuinely needs row-level data, so they wait for production output checking
from ACRO, the UK SDC community's output-checking tool); anything across
sessions or colluding users (differential privacy
is the roadmap answer); and it remains a research prototype on synthetic
data — see the [non-goals](specification.md#non-goals-what-it-does-not-claim)
and the [roadmap](roadmap.md).
