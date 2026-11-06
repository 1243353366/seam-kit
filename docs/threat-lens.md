# THREAT-LENS: four threat classes, four failure points

Worms, trojans, commercial software and ransomware all depend on an execution environment, trust
relationships and assumptions. That shared sentence is true and useless, because they fail in
different places. `lab/threatlens/` is a package with one engine per class (`worm.py`, `trojan.py`, `software.py`,
`ransomware.py`), a shared `correlate.py`, and `record.py` which produces the evidence record a case
store can hold. `lab/telemetry.py` is the schema they all read, and `lab/simulate_incident.py`
provides the benign event shapes to test them against.

| class | fundamental dependency | what is graded | ATT&CK pointers (as labels, not compliance) |
| --- | --- | --- | --- |
| worm | propagation | fan-out, repeat attempts, service creation across hosts | T1021, T1570 |
| trojan | user and system trust | ancestry, autostart writes, first-contact egress | T1059, T1547, T1041 |
| software | vendor and dependency trust | drift from a verified baseline: digest, version, destinations, telemetry volume | T1195 |
| ransomware | file access and operational control | write bursts, recovery-artefact deletion, egress ahead of impact | T1486, T1490 |

The ATT&CK identifiers are labels on observations so a report can be read by someone who thinks in
that taxonomy. Nothing here claims coverage, and no technique is inferred from a name.

## What is never an input

Malware names, file hashes, vendor signatures and file contents. `investigate()` takes events, an
optional baseline and optional known destinations, and the report states what it did not use. A
process called `ransomware.exe` that does nothing is graded `unknown`, which is the test that keeps
the rest honest. A valid code signature appears only as a limitation: it proves who built a file, not
what the file does.

## Independence, counted honestly

The audit that reviewed this repository found an adjudicator treating two signals on the same pixels
as corroboration. The same error is easy to make here in a different costume, so independence is
counted in **telemetry sources**, not observations:

- a write burst and a deleted shadow copy are both file metadata, and count once between them
- fan-out and repeat attempts are both network telemetry, and count once
- fan-out plus service creation on several hosts is two sources
- a burst plus egress ahead of it is two sources

One source gives `suspected`, two give `corroborated`, and nothing inside the machine gives
`confirmed`. Confirmation is an examiner determination backed by a record kept elsewhere.

## The research proposition

The target is stated plainly: can unfamiliar behaviour be identified without known-malware
signatures? The tests answer a narrower question than that, and the difference matters.

**What is shown:** the analysers detect the four behaviours in simulated event streams, with a benign
control that produces nothing, and with the independence rule enforced by tests that fail when a
second observation from the same log is allowed to raise the grade.

**What is not shown:** that this works against real malware on a real endpoint. The simulators emit
the shapes a sensor would produce; they are not captures, and no real sample was executed anywhere.
There is no endpoint agent, no ATT&CK coverage measurement, no false-positive rate on production
telemetry, and no containment testing. The recovery-interference check reads delete paths, so it
sees an explicit deletion and not a volume that quietly stops taking snapshots.

Reference frameworks used as design references: MITRE ATT&CK for the behaviour vocabulary, MITRE
D3FEND for what a defender could do at each step, CISA's incident response guidance for the
preserve-then-act ordering, NIST for evidence handling. None of them is satisfied by this module and
none is claimed.

## Where this connects

`lab/conceal.py` covers what an attacker removes after the fact, `lab/adjudicate.py` covers what media
can support, and THREAT-LENS covers what a host did. All three end the same way: a grade, the evidence
behind it, and the limits that stop it from being more. Ransomware's data-exposure problem is the
clearest example of why: restoring the files does not undo the exfiltration, and an egress observation
is the only thing here that speaks to it.

## The telemetry schema comes first, and it refuses things

`lab/telemetry.py` defines seven event kinds (process, file, network, service, auth, privilege,
config) with per-kind required fields, and `check()` raises rather than guessing. This exists because
the alternative is four engines each inventing its own reading of "a file event". It also refuses
invented vocabulary: a file operation of `exfiltrate` is a schema error, not a detection, and a
privilege event must say `elevated: true` or `false` rather than carry something truthy.

`investigate()` collects `schema_problems` instead of throwing when `strict=False`, so a malformed
stream can still be examined and the malformation is reported rather than silently dropped.

## The evidence record

`record.py` turns a correlation report into the shape a case store holds: case, host, per-finding
observations, which telemetry sources corroborate them, the alternative explanations, and a
conclusion. The conclusion is one of two sentences and neither contains the word "detected":

- ``behaviour requiring examiner review; two or more telemetry sources agree``
- ``behaviour requiring examiner review; one telemetry source observed it``

Every finding carries its benign twins. A ransomware burst is also a bulk backup, a software update
rewriting its files, or a legitimate mass file conversion. A detector that cannot name an alternative
has not finished. `as_text()` renders the block the earlier proposal sketched, and `confirmed` is
`False` in the record itself so a downstream reader cannot mistake a grade for a determination.

## Corrections from the external review

Three of the five reported defects were real and are fixed with tests: correlation graded on detector
labels rather than telemetry sources, lexical version comparison, and a validation fallback that kept
malformed events and let an engine raise instead of returning a controlled result.

One was already guarded and is worth stating plainly, because the report and the code disagreed: the
egress comparison short-circuits on `if egress_baseline` before dividing, so a zero baseline never
reached a division. A *negative* baseline did slip through and produced a negative ratio with a
straight face, which is worse than a crash in a forensic tool. It is now refused.

The fifth was a reporting complaint, not a grading one: the write burst and the recovery deletion were
already deduplicated into one file source, but the explanation for that was printed among the
observations. It reads as a limitation now, which is where a statement about evidence quality belongs.

The review also asked that the correlation rule carry its own caveat. It does: source labels do not
establish statistical independence, and two sensors can share collection infrastructure. Correlation
by host and time additionally assumes synchronised clocks, which this repository does not verify.

## Second review pass

A second review of commit `73e5bf9` reported four code defects. Three of them had already been fixed
in the following commit, `48417c8`, which that review did not see: correlation graded on detector
labels, lexical version comparison, and a validation fallback that let malformed events reach the
engines. Each carries its regression test.

The fourth was new and real. `lab/telemetry.py` rejected NaN and allowed infinity, so a timestamp of
`inf` validated and then entered the burst-window arithmetic and the egress ratio. Every numeric field
that feeds arithmetic must now be finite, and an infinite event is counted in `events_rejected`
instead of being analysed. That is the difference between a check that looks complete and one that is.
