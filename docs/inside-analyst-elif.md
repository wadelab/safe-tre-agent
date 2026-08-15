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
as the assistant, and given the study's nine-question exam three times in an
afternoon while we fixed what each run taught: on the last run it got **nine
out of nine** verdicts right, every number in every summary traced to a
released table, and the audit chain verified. It found the five-fold rise in
stake with night use, showed it survived splitting by employment, called the
charity question a null (significant but negligible — the trap the study set,
and the one it fell into on the first run), found the summer peak and the
larger late-night bet, saw harm rising over the year for heavy users only,
and refused the three questions it should refuse — two of them without asking
a single query, on the strength of the catalogue alone. Where it is still
green: it stratifies by hand instead of fitting the adjusted model that would
be sharper, and it stops after a few steps of a twenty-step budget. Nine
questions and one model is a first measurement, not a result; but every miss
on the way was a defect in the instructions we hand the model, and those are
ours to fix.

### What it still does not do

- It cannot see raw data, even in the middle of an analysis. An analyst that
  could — to look at residuals, say — is a real research problem (every
  choice it makes could leak a bit), and it is deliberately **not** built.
- It does not replace the human output checker; it gives them a dossier
  instead of a pile of queries.
- Everything is on synthetic data.
