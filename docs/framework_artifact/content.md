---
title: The keep, and who guards it
eyebrow: A companion to the bestiary
subtitle: The bestiary was the monsters. This is the castle — how a safe data haven
  actually works, and why a mere human can believe it when an AI wrote most of the code.
---

<!-- Edit the prose freely. Images are `![alt](NN_name.png)` from
     docs/figures/framework/standalone/. Rebuild:
     uv run python scripts/make_framework_page.py -->

The bestiary was a menagerie of everything that can go wrong — every way a
supposedly-safe data service can quietly hand over someone it should have
protected. Useful, and a bit terrifying. This is the other half of the story,
and a more reassuring one: the castle those monsters keep trying to break into,
and the four characters who guard it.

The problem is the same as before. I can't hold the whole system in my head —
an AI wrote most of the code, and there is a *lot* of it. So, same trick: turn
the machinery into characters I can actually remember, and keep the real record
one click behind each of them.

## The Guide and the Raven

![The Guide and the Raven](01_overview_standalone.png)

A researcher has a perfectly ordinary question — *how many patients over 70
stayed more than a week last year?* They don't get to wander into the vault and
rummage. They tell the AI Guide, in plain English, and the Guide's only job is
to turn that sentence into a strict, formal query: a form with boxes, nothing
more.

The important words on its banner are **translation, not authority**. The Guide
doesn't decide what's allowed — it *can't*. It proposes a query, and only that
tiny query is sent, carried by a raven across a deliberately thin link. The data
never leaves the walls. If the Guide were compromised, or hallucinated, or got
talked into something silly, the worst it can make is a form the keep is going
to check anyway.

## The Oracle in the Keep

![The Oracle in the Keep](02_oracle_in_the_keep_standalone.png)

Inside, the query runs a gauntlet. A gate that accepts only the formal form. An
Oracle that reads what was actually asked. An engine that computes
*aggregates* — counts, averages, totals — never rows. Then the checks: the
disclosure rules that suppress a too-small group, or one dominated by a single
person, or anything that would single someone out. Every decision is written
into a tamper-evident log. Only then does an approved, rounded, safe result
leave.

The motto underneath is the whole point: **raw data stay inside the keep**. What
comes out is a summary that has survived every guard. Least privilege, defence
in depth, and — because I have to be able to check it later — everything written
down.

## Lean, the Proof Owl

![Lean, the Proof Owl](03_lean_the_proof_owl_standalone.png)

This is where it stops being hand-waving. Testing shows a thing works for the
cases you thought of. The owl does something stronger: it *proves* the rules
hold for **every** possible query — including the millions nobody will ever
type. *Assume A, derive B… property holds. Q.E.D.*

So some of the nightmares in the bestiary aren't merely caught — they're made
impossible to even ask for. You can't request a raw record, because there is no
box for one on the form, and the owl has proved there never will be. Its motto,
**prove, don't assume**, is exactly the discipline a nervous human wants when an
AI wrote the code.

## Alloy, the Brass Tracker

![Alloy, the Brass Tracker](04_alloy_the_brass_tracker_standalone.png)

The owl is rigorous but literal: it proves what you asked, under the assumptions
you gave it. The real danger is an assumption you didn't know you were making —
and that's the tracker's job. It's a curious brass creature that *explores*: it
builds a small world and walks every path through it, systematically, hunting
for a counterexample — a state where the rules quietly fail.

It doesn't prove things the way the owl does; it **searches**, fast and
exhaustively, across a bounded little universe, and it's very good at spotting
the edge case a human skimmed past. The two cover each other. The owl says *this
can never happen*; the tracker says *let me try very hard to make it happen
anyway*. When it finds a crack — and it has — that's a bug caught before it
shipped.

## So do I trust it?

Not blindly; that would be its own kind of monster. But I don't have to hold the
whole thing in my head. The Guide keeps the AI on the untrusted side of a thin
wall. The keep checks every result and records why. The owl proves the boundary.
The tracker goes looking for the proof's blind spots. Between them the *shape* of
the thing is checkable — and that is the most a mere human can honestly ask for.

The monsters are in the bestiary. This is the castle they keep failing to get
into.
