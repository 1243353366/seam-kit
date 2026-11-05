
## EvidenceGraph: what the observations can support

`lab/graph.py` takes sightings, access events and their clock declarations, and grades every
conclusion:

| Grade | Means |
| --- | --- |
| confirmed | holds even with both clocks at the generous end of their declared uncertainty |
| corroborated | two intact sources agree and nothing contradicts them |
| suspected | the arithmetic points one way, the evidence cannot close it |
| unknown | the question cannot be answered from what is here |

The confirmed grade carries a deliberate margin. A 320 km/h limit is a modelling assumption, so a
contradiction sitting just above it is a bad assumption rather than an impossibility. The claim
becomes confirmed only past 1.5x the limit, with identity verified and custody intact at both ends.

On `lab/fixtures/lupin-case.json`: one confirmed contradiction (Paris 14:02 and Lyon 14:05, 392 km
apart), one suspected (Marseille to Lyon, impossible arithmetic, but the Marseille sighting was
never identity-verified), one unknown. Running the fixture twice gives the same grades, because
every threshold is a constant and every clock is declared rather than assumed.

## BinaryLab: investigate a binary you compiled

`lab/binarylab.py` builds `binary/scorer.c`, compares it against an independent implementation
written from the documented behaviour rather than from the source, sweeps ten adversarial inputs,
and reports every divergence. `binary/scorer_bug.c` carries a one-character change and the sweep
catches it, which is the entire point: a differential harness that has never caught a real
divergence is a harness that agrees with itself.

The structural view (symbols, call sites, instruction count) ships with its own limits attached.
Symbols vanish under strip, instruction counts move with the compiler and optimisation level, and
neither establishes behaviour. They corroborate. The sweep establishes.

## What is not built

No video pipeline, so temporal and audio-visual signals remain untested. No face detection: the
synthetic corpus supplies ground-truth regions, which is honest for a controlled study and useless
as a detector. Claims are stored in the same case database as exhibits but are not themselves
hash-chained yet, so a claim can be altered without breaking the exhibit chain.
