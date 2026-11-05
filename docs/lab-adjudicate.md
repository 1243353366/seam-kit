# The adjudicator: what a verdict is allowed to claim

The detector answers a narrow question. This module is the part that decides what the answer
permits, which is a different problem and the harder one.

## Two claims, one ceiling

- `media_synthetic`: these pixels were produced or altered by a generative process.
- `event_false`: the recorded event did not happen.

Media evidence can support the first. It cannot support the second, because a fabricated clip and
a real event later altered look identical from inside the frame. `event_claim()` therefore caps at
`unknown` unless an **independent** non-media source contradicts the event. The ceiling is code, so
a test fails if it is removed. The test exists: `test_confirmed_media_alone_still_cannot_claim_the_event_was_false`.

## The grade ladder

| Grade | Requires |
| --- | --- |
| confirmed | provenance with an identified insertion point **and** an intact custody chain **and** at least one agreeing signal |
| corroborated | two or more independent signals agreeing |
| suspected | one signal |
| unknown | nothing, which is not innocence |

Every claim carries `limitations` whether or not it scored well. A broken custody chain blocks the
top grade outright: provenance you cannot verify proves nothing.

## Held-out evaluation

Fitting on generator families you have already met is not a measurement. `evaluate()` fits on two of
three families and scores the third.

| family | AUC | detection @5% FPR | FPR | Brier |
| --- | --- | --- | --- | --- |
| smooth | 1.000 | 1.00 | 0.00 | 0.000 |
| light | 1.000 | 1.00 | 0.00 | 0.000 |
| hard **(held out)** | 0.328 | 0.00 | 0.00 | 0.484 |

The held-out row is the only honest number, and it is the finding: **0.328 AUC and a Brier
score of 0.484, worse than always saying 0.5.** The signals were partly detecting the donor's
smoothing, so a generator that does not smooth defeats them, and nothing in the training set warned
anyone. This is distribution shift reproduced in a controlled setting, which is what the lab is for.

## Calibration

`fit_logistic` maps a raw score to a probability, `brier` scores those probabilities, `reliability`
bins them. A coin that always says 0.5 scores 0.25; the held-out family scores above that, meaning
the stated confidence is actively misleading rather than merely uninformative.

## What this does not establish

No video pipeline, no audio-visual synchronisation, no face detection, no unseen real-world
generator. The families here are parameter variations of one synthesiser I wrote, so the holdout
tests whether the method survives a *known* kind of difference. A real distribution shift is worse.
