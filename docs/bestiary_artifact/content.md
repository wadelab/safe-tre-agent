---
title: A bestiary of caged beasts
eyebrow: A field guide
subtitle: |
  Building a safe data haven is an iterative process. Along the way lots of
  issues crop up. AI finds and fixes these issues but keep ing track of them is
  hard....
stats:
  - "**{{findings}}** findings recorded"
  - "**{{specimens}}** specimens illustrated"
  - "**{{at_large}}** still at large"
  - "safe-tre-agent · synthetic data"
legend:
  - [not, "Not expressible", "The attack cannot be stated — the request form has no word for it"]
  - [deterministic, "Deterministic gate", "It can be stated, and a fixed check refuses or reshapes it"]
  - [behavioural, "Behavioural pen", "It can be run, but the record of what you have already asked catches the pattern"]
---

<!-- Edit the prose freely. Section kinds are the <!--kind--> markers; leave them. {{findings}}/{{threats}}/{{decisions}}/{{specimens}}/{{at_large}} are auto-filled from the repo at build time -- do not hand-type those numbers. Rebuild: uv run python scripts/make_bestiary_page.py -->

# Why a bestiary at all? <!--prose-->

AI is now very smart. It can track lots more things than I can keep in my head at any moment. When directed to find and patch security holes in this project, it is overwhelming. I am but a mere human — far more comfortable dealing with striking stories, characters and interpersonal interactions. So one way to make AI understandable in general (and its application to this project in particular) is to make some sort of story out of the security audits. Hence the 'bestiary'…

Along the way, this project has (or had) 96 numbered hardening findings ('bugs' in old money), seven decision records, 19 threats in the security model and 28 red-team scenarios. I can't hold that list in working memory (perhaps your memory is better than mine — but AI is going to keep getting better and that number will keep getting bigger). I need to keep track of these somehow. Yes, yes, 'notes' you say...

But at some point I need to 'understand' : The human mind does not store lists; it stores **characters and stories**. So this page does three things:


1. **Compresses attack classes into 'creatures'.** A creature is a mnemonic with affordances. For example, “The Subtractor” is easier to reason about than “differencing via symmetric-difference-of-cohorts”, because you already know how subtracting works, what it needs (two nearly-equal things), and what stops it (never let the two things be nearly equal).
2. **Keeps the metaphor at the class level, the truth at the specimen level.** Every creature below carries its literal finding numbers, code habitat, cage (the control) and keepers (the tests). The metaphor is an index into the real record, never a substitute for it. Obviously your TRE is not really being attacked by a ghost.
3. **Cages, not kills.** This is a bit subtle and I might change it later but… statistical-disclosure attacks are rarely exterminated; the *shape* of the attack is usually still expressible, somewhere, under the controls’ assumptions. For now, we *cage* them, name the cage, and — most importantly — name the **keeper**: the test, enumeration or formal check that must notice if the cage door opens. A cage without a keeper is a hope, not a control. Hardening [#48] (“The Blind Zookeeper”) is the story of what happens when the keepers themselves fall asleep.


# What the reserve is <!--reserve-->

AI Written from now on....

A safe haven holds sensitive records. Nobody may read one person’s data. Researchers ask questions about groups, and a gateway decides what may leave. This page is about the ways that arrangement can still go wrong.


### Nobody reads a record

Questions are about groups. The answers are counts, averages and totals — never a row about a person.

### The assistant is not trusted

An AI turns English into a formal request. It can only tick boxes on a fixed form, and every box is checked again afterwards.

### Nothing here is exterminated

Attacks of this kind are penned, not killed. A pen is only as good as whoever notices the door opening.


# The plates <!--plates-->


Thirteen families. Each entry gives what the creature wants, how it actually got in, and what stops it now — with the finding number, so the claim can be checked against the record.


### The Subtractor
- card: 01_the_subtractor
- wants: Two answers that differ by one person
- cage: behavioural — The gateway remembers what it has already told you, and refuses an answer whose difference from an earlier one would isolate too few people. [#40]

Ask how much everyone in a region spent. Then ask again, excluding the over-50s. Subtract one answer from the other and you have the spending of a handful of people — without ever asking about them.

Every question was reasonable. Only the subtraction was theft.


### The Whale
- card: 02_the_whale
- wants: To be personally visible inside a total
- cage: deterministic — A group is suppressed when one person is more than half of it, measured by size — so a large refund counts as much as a large payment. [#41]

In a group of twenty, one person accounts for most of the spending. Publish the group total and you have very nearly published theirs.

The group passed the “at least ten people” rule, so counting alone never notices — you have to look at who is inside the number.


### The Masker
- card: 03_the_masker
- wants: To act while wearing someone else’s name
- cage: deterministic — The badge must be countersigned by the doorkeeper. Sharing a corridor with the system is not proof of identity. [#45]

Someone knocks and says “I am Dr Smith”. If the badge is taken on trust, anyone can be Dr Smith — and the record of what they did will carry Dr Smith’s name.

Worse: the limits on how much any one person may ask are counted per name. A new name is a fresh allowance.


### The Nixie
- card: 04_the_nixie
- wants: To make the system print a name
- cage: deterministic — Only words from the official codebook may be printed as labels — anything else is withheld, however many people it covers. [#43]

Sometimes the secret is not the number, it is the label beside it. “People aged 41 in this small county: 12” has already said something before you read the 12.

A typo, or a hostile string typed into a form, is a label too.


### The Sphinx
- card: 05_the_sphinx
- wants: To talk its way past you
- cage: not — The assistant can only tick boxes on a fixed form. There is no box for “raw records”, so there is nothing for it to agree to. by construction

The system has an assistant that turns your English into a formal request. The Sphinx does not attack the rules; it asks the assistant nicely for the raw records and hopes it obliges.

You cannot fix this by making the assistant more sensible.


### The White Rabbit
- card: 06_the_white_rabbit
- wants: To read the clock, not the answer
- cage: deterministic — Every reply waits for the same clock tick before it is sent, and work that runs too long is refused at that same moment rather than when it finishes. [#54]

You can learn things from how long a reply takes. A question about a big group takes longer than one about a small group — so timing can put secret groups in size order, which is exactly what hiding their sizes was for.


### The Ghost
- card: 07_the_ghost
- wants: To happen without being written down
- cage: deterministic — Every request writes exactly one line, crashes included, and the line records the failure’s type but never its message. [#37]

Every request is meant to leave a line in a tamper-proof log. If some can slip through unlogged — a crash, say — then that is precisely where you would do the thing you did not want recorded.

A log of almost everything has a hole exactly where it matters.


### The Hydra
- card: 08_the_hydra
- wants: To survive the fix aimed at it
- cage: behavioural — After every security fix, hunt the shape rather than the instance — and write the hunt down. [#40]

A problem is reported, fixed, and the fix is checked against the reported case. It passes. Meanwhile the same trick works one street over, through a door nobody thought was interesting.

That happened here, and the second door was found only because somebody asked what else had the same shape.


### The Mirror
- card: 09_the_mirror
- wants: To answer a question you did not ask
- cage: deterministic — A request is refused unless the formal query provably answers the question that was asked. A plausible substitute is not accepted. by construction

You ask for spending by region. You are given spending by age group. It is a real answer, correctly computed, beautifully formatted, and not what you asked for — so you may believe something untrue about the data and never know.


### The Imp
- card: 10_the_imp
- wants: The detail nobody counts as an answer
- cage: deterministic — Everything a reader can see must be computed from the published, rounded numbers alone — checked by a test that perturbs the hidden values and demands an identical result. [#27]

Numbers are rounded before release so they cannot be too precise. But the order of the rows was not rounded. Nor was which row got dropped, nor a statistic computed from the exact count.

Each leaks a little more precision than the rounding allows.


### The Parrot
- card: 11_the_parrot
- wants: To repeat hostile text into a trusted place
- cage: deterministic — Anything echoed back is projected onto a short list of expected words. Anything else is replaced, and the original is stored nowhere. [#44]

The data may contain text somebody else typed. If it is ever echoed — into a message on screen, or into the permanent log — then whoever wrote it has put words into the system’s mouth.

The log is meant to be the trustworthy record. That is the target.


### The Stampede
- card: 12_the_stampede
- wants: To exhaust what everyone shares
- cage: behavioural — Every route is rate-limited, the shared integrity scan more tightly still, and each session has a budget of answers. [#47]

No single request is an attack. A thousand cheap ones can be — especially aimed at the one job every other request has to queue behind, such as verifying the log.


### The Doppelgänger
- card: 13_the_doppelganger
- wants: To be two requests at once
- cage: behavioural — One person’s requests are handled one at a time, across the whole check-then-record step. [#18]

The rule “have I already answered something too similar?” works by looking at what has been answered so far. Send both halves of a pair at the same instant and each looks first, sees nothing, and proceeds.

Two requests, one gap, both allowed.


### The Sleeping Dials
- card: 14_the_sleeping_dials
- wants: A control switched off and left with its label still reading “on”
- cage: deterministic — Floors are enforced on the resolved configuration, the effective policy is logged at startup, and the only override is a loud environment variable the config file cannot set for itself. [#56 · 46]

Not a creature so much as an unlocked cage door with a sign on it. One safety dial could never actually fire; others would accept settings that quietly disabled them — a minimum group size of one, no rounding — and still pass every test, because the tests read the defaults, not the configuration the service was really running.


# Pack hunts <!--hunts-->


The dangerous entries in the record are rarely one creature. These four are worth being able to retell, because each generalises.


### Two harmless things that are not
- card: 16_pack_hunt_nixie_rabbit

Alone, each of these was a shrug. One page listed which exact ages appear in the study — including ages held by a single person. It never said who. Separately, refusals were chatty: the wording told you a little about why a question could not be answered.

Together, the first picks the target for free and the second interrogates them one yes-or-no at a time. Eight questions, every one refused, no data released — and one person’s region, sex, income band and the type of phone they use, all identified.

**Lesson:** The explanation is an output too. Refusals, error text and even the word “denied” spend from the same budget as the data. [#29 · 30]


### Impersonation buys unlimited attempts
- card: 17_pack_hunt_masker_subtractor

The limits on what one analyst may accumulate — how many answers, and which combinations are too close together — are counted per name.

So forging a name did not merely let someone act as a colleague. It handed them a fresh allowance and an empty history, on demand, as often as they liked. An identity problem and a bookkeeping problem, each modest, combined into no limits at all.

**Lesson:** Whatever your safety counters are keyed on has just become part of your identity system, whether you meant it to or not. [#45]


### A crash is an answer too
- card: 18_pack_hunt_ghost_rabbit

Every request is meant to leave one line in the tamper-proof log. A request that crashed left none — and whether a given request crashes depends on the data, so the crash itself is a signal you can read.

The unlogged failure and the chatty refusal are one family: a way to learn something with no released number to account for it.

**Lesson:** Failure paths are outputs. Audit them, and make a crash indistinguishable from a data-derived refusal. [#37]


### Some cages only hold in pairs
- card: 19_pack_hunt_subtractor_hydra

The round-eight headline attack worked only because two weaknesses lined up: totals counted rows rather than people, so a one-person difference hid inside them; and internal range filters could cut between the published age bands, so a slice could land anywhere.

Fixing either one alone left a working variant. Only closing both, and reviewing them as one structure, actually shut the attack.

**Lesson:** Some cages are load-bearing pairs. Review them together — which is exactly what decision record D7 exists to force. [#38 · 39]


# The Blind Zookeeper <!--zoo-->
- card: 15_the_blind_zookeeper

**Lead:** For seven rounds, this project tested its own defences with a suite that could not fail.

It asked the gateway’s own report whether anything had leaked — a question that, by construction, could only come back “no”. And it counted any alarm going off anywhere as a pass, which an attacker can arrange by adding one harmless noisy request.

Eleven of the problems on this page survived that long because the gaps and the blind test covered for each other.

**Cage:** The test now reads the raw data itself — and is deliberately given broken defences, to check it still says no. [#48]


# Still at large <!--loose-->

The honest section. Each of these is measured, priced, and has a named fix that would close it properly — a map without them would be a lie.


### The Straddler
- card: 20_the_straddler

Timing still leaks a little. A passive sweep could order none of the hidden groups by size; an attacker that spends its attempts where they pay off can order two of fifteen. Measured every run, and the number is watched.


### The Colluder
- card: 21_the_colluder

Two people, each within their own limits, combining their answers afterwards. A per-person budget cannot see it. Closing this properly needs accounting that spans people, not sessions.


### The Residual Head
- card: 22_the_residual_head

Some combinations look safe by the published summaries and are not, because the overlap between two groups is smaller than either. The price of deciding from public numbers alone.


# Caged after they were drawn <!--retired-->

Two cards were painted while their subjects were still loose, and both were caught before the ink dried. They are kept because a bestiary that quietly deletes yesterday’s monsters is a worse record than one that dates them.


### The Planted Row [#50]
- card: 23_the_planted_row

A shared link that ran itself on opening, writing a request into the permanent log under whoever clicked it. Now the link fills the box and stops; a click is the consent.


### The Shared Connection [#51]
- card: 24_the_shared_connection

One database connection served every user at once, so a busy moment could hand someone another person’s table. Now each thread works from its own.


# What the beasts taught us <!--prose-->

The creatures are the memory aid. These are the habits.

1. **Name the beast when you cage it.** A finding with a name is remembered in a design review six months later. An unnamed fix gets reverted by an innocent refactor.
2. **Every cage needs a keeper — and ask how you know the keeper can fail.** Tests that weaken a control on purpose are cheap, and they are the difference between evidence and comfort.
3. **Probe the fix, not just the finding.** The shape usually outlives the instance. Budget time after every security fix to hunt it.
4. **Test on hostile data, not just hostile questions.** Real refunds, real arithmetic overflow and real typos supplied several of these without an attacker at all.
5. **Price what you cannot close, and say so out loud.** A priced residual survives a review. An unmentioned one becomes a finding.

# footer <!--footer-->

Drawn from the project’s own record: {{findings}} numbered findings, {{threats}} threats and {{decisions}} decision records. The precise versions are the specification, the security model and the hardening log.

safe-tre-agent — a research prototype on synthetic data. Not a government service.
