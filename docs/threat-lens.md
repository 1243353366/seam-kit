# THREAT-LENS: four threat classes, four failure points

Worms, trojans, commercial software and ransomware all depend on an execution environment, trust
relationships and assumptions. That shared sentence is true and useless, because they fail in
different places. `lab/threatlens.py` treats them as four analysers rather than one detector, and
`lab/simulate_incident.py` provides the benign event shapes to test them against.

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
