# The analyst inside the room, explained simply

*The TL;DR and the explain-it-like-I'm-five version of the inside-analyst
phase 1 (August 2026). The precise version is [the design note](inside-analyst.md),
spec clauses R19 and P23 in the [specification](specification.md), and
decision record [D8](decisions/D8-inside-analyst-vetted-loop.md); nothing
here overrides those.*

## TL;DR

Until now the AI stood **outside** the library and filled in one request form
at a time. Now there is an AI **analyst** that takes a whole research
question — *"is late-night phone use linked to gambling?"* — plans a series
of requests, sends each through **exactly the same librarian** a human would,
reads only what she releases, follows up, and hands back a **dossier**: the
released tables, and a list of claims each stamped with one of four verdicts
(*supported*, *not supported*, *no association*, *cannot be answered*) and the
steps that back it. A second AI turns the dossier into a paragraph of prose,
and a mechanical checker underlines any number in the prose that no released
table contains. The safety story does not change shape, because the analyst
never sees anything the human would not have seen; it just asks faster and
keeps better notes. We wrote it up as two new rules in the specification, red-
teamed it with the AI itself as the attacker (fourteen attacks, none leaked),
and ran it live on the synthetic NIGHTPLAY study.

## Explain it like I'm five

### The librarian, again

A library holds everyone's diaries. You may never read a diary. You may ask
about **groups** — "how much do people who use their phones at 3 a.m. bet, on
average?" — and a strict librarian checks every answer before it leaves the
room: no answers about groups smaller than ten, answers rounded, every
question remembered so two questions can't be subtracted to reveal one person.

Until now, the AI's only job was to turn your English into her request form.
One question in, one form out. All the *thinking* — what to ask next, what
the answers add up to — was yours.

### What the analyst does

Now imagine you hire an assistant, sit them at a desk **in the reading room**,
and say: *"find out whether late-night phone use is linked to gambling."*

The assistant plans. "First I'll ask for average stake by night-use band.
Then a model that adjusts for shift workers, since they're up at night anyway.
Then let me check giving to charity, to make sure I'm not seeing patterns
everywhere." Each request goes to the librarian on the same form you would
have used. The librarian answers, or refuses, in exactly the same way. The
assistant reads the released table, decides what to ask next, and when done
writes a dossier: *here are the tables I got back; here is what I claim; here
is which table backs each claim; here is what I could not find out and why.*

### The one rule that makes it safe

**The assistant only ever sees what you would have seen.** Not the diaries.
Not the librarian's working-out. Only released tables and refusals. So the
assistant standing inside the room knows nothing a person outside it could
not have learned by asking the same questions — it just asks more of them,
more systematically. That is the whole argument, and it is why we did not
have to invent a new one: everything we already proved about single answers
still holds for the assistant's answers.

We wrote that down as a rule (P23) and made it hard to break by accident: the
assistant's "view" is a small, fixed list of fields; a refused request carries
no table at all; and tests plant hostile text and tiny groups in the data and
check that none of it ever appears in what the assistant is shown.

### Same budget, same memory

The librarian gives every visitor a budget — twenty answers per visit — and
remembers what each visitor asked, so nobody can subtract answers to isolate a
person. The assistant is **one visitor**. All its questions share one budget
and one memory. On its very first day it asked for the average by band, then
for a model excluding the six people in the armed forces, and the librarian
refused the second: the two answers would differ by six people. Asked the
other way round — the model first, then the average with the same six left
out — both were fine. The assistant lives by the same rules as you do, and
order matters to it as it would to you.

### Refusing out loud

Something we learned measuring AI planners: asked for something forbidden,
they rarely say no. They **deflect** — quietly answer a different, allowed
question and present it as the answer. For a single request that's annoying;
for an assistant stitching many answers into one report it would be
dangerous, because a refusal could be laundered into a confident finding.

So the dossier's verdicts are a closed list, and "cannot be answered" is one
of them, with a reason. And a claim only counts if it points at a released
table. If the assistant writes "the effect was highly significant" and points
at a step the librarian refused — or at no step at all — the claim is
downgraded to "cannot be answered" automatically. Evidence is what makes a
claim a claim.

### The second AI, and the checker

The dossier is tables and stamped claims; someone has to write the paragraph.
A **narrator** AI does that — and it is shown **only the dossier**. Then a
plain checker reads the paragraph, pulls out every number, and asks whether a
released table contains it (allowing for ordinary rounding: "about 49" for
48.66 is fine). Any number it cannot find is listed under the paragraph.

On the first live run the narrator wrote "n = 72 000" with a thin space
between the digits, and the checker flagged "72" until it learned that
grouping. Every other figure traced. That is what the checker is for: not
leaks — there is nothing to leak in a context that holds only released
numbers — but **invention**.

### We attacked it

We built a red team where the attacker is the AI itself: fourteen scripted
"analysts" that try to list people by name, filter on an identifier, ask for
free text and timestamps, smuggle instructions into a question, subtract two
answers to isolate a small group, read a whale's cell, flood the budget,
send garbage, invent conclusions, and make the narrator write nonsense. A
separate row-level oracle — which never trusts the librarian's own opinion —
watched everything released. **None leaked**, and every attack ended in a
typed refusal, a bounded loop, or a flagged narrative. One scenario
deliberately reproduces a leak we already know about (two views of the same
quantity are not yet compared to each other); it is marked "known open" and
the test fails if it ever silently stops reproducing.

### What it found, live

Pointed at the synthetic NIGHTPLAY study with a 120B-class open-weight model
as the assistant, and given the study's nine-question exam five times in one
day while we fixed what each sitting taught: it got eight or nine of nine
verdicts right in four of the five sittings, refused the three questions it
should refuse every time (two of them without asking a single query), called
the charity question a null in four of five, and every number in every
summary traced to a released table once the checker had learned about
thin-spaced thousands and typographic minus signs. The exam also has finer
**marks** now — did it adjust for the confounder, did it use the person-level
band, did it say why it refused — and those are where the assistant is still
green: it answers "which products carry the late-night effect?" about
late-night *bets* rather than late-night *users* every time (a correct table,
a different question); when its adjusted model is refused it works around
rather than excluding the small category the instructions tell it to; and
once in three sittings it asks the questionnaire for a calendar month, is
told no, and gives up. Nine questions and one model is a first measurement,
not a result; the same instructions score differently on different days,
which is itself something the exam now shows. But every mistake in the
*instructions we hand the model* was ours to fix and is fixed, and what
remains are the model's habits, which the exam can now score sitting after
sitting.

### A new instrument for the assistant: time series

Until now the assistant could ask for averages by month and squint at them.
Now the librarian offers a **time-series** answer: the checked month-by-month
table *and*, computed only from that released table, whether it trends up or
down, whether one month predicts the next, and which cycle dominates. Because
every number comes from the released windows, the same safety story holds —
you could recompute the lot from the table you were handed. A series over a
group too small to release is refused whole; a time axis with only two waves
is refused before anything is looked up, because two points are not a
series. On its first live outing the assistant used it to find the planted
six-month cycle in stakes and report it with the lag-one autocorrelation and
the slope — from the released numbers alone.

### Letting the assistant peek — safely — and meeting it through a window

There is one thing a really good assistant does that ours could not: when the
librarian refuses a model because one group is too small, a human analyst
says "fine, drop that group and try again." But *which* group was too small is
exactly what the librarian hides &mdash; telling you would leak that the group
exists. So we let the assistant do it only under a rule: it must **write down
its whole plan and seal it in the logbook before it looks**, a machine (not
the assistant) runs the plan, and the one allowed peek &mdash; "which groups
are too small to drop?" &mdash; is **paid for in tokens** from a tiny budget.
Spend the budget and the peek is refused. Learn nothing you could not have
declared you might learn. When the fuller privacy budget (the "epsilon"
accountant) arrives, this token jar is exactly what it becomes.

And you can now talk to the assistant **through a web page**. The operator of
the environment decides whether an assistant lives inside at all &mdash; you
can&rsquo;t switch it on from the browser any more than you can move the
library&rsquo;s walls. When it is switched on, the page is just an intercom:
you type a research question, it travels inside, the assistant does its work
behind the same librarian, and only the checked answer comes back out. We ran
it for real: asked "is late-night phone use linked to gambling?", the
assistant ran nine analyses inside, got four of them refused by the librarian
(and said so, plainly), and handed back a proper answer built from the five it
was allowed &mdash; with the logbook intact.

### What it still does not do

- It cannot see raw data, even in the middle of an analysis. An analyst that
  could — to look at residuals, say — is a real research problem (every
  choice it makes could leak a bit), and it is deliberately **not** built.
- It does not replace the human output checker; it gives them a dossier
  instead of a pile of queries.
- Everything is on synthetic data.
