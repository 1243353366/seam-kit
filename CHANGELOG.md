# Changelog

## 2026-11-05 - THREAT-LENS 0.3: schema, engines, evidence record

- **New: `lab/telemetry.py`.** Seven event kinds with per-kind required fields; `check()` raises on
  unknown kinds, invented file operations, missing hosts and non-boolean privilege flags.
  `investigate()` reports `schema_problems` instead of dropping malformed rows.
- **Split into engines.** `lab/threatlens/` with `worm.py`, `trojan.py`, `software.py`,
  `ransomware.py`, `correlate.py`, `record.py`. The public names are unchanged.
- **New detections:** rename bursts, extension churn, weakened recovery configuration (its own
  source), privilege escalation beside ancestry, publisher change, new bundled dependencies, new
  privileged services, and propagation shapes that only become edges when the hosts talk to each
  other.
- **New: `evidence_record()` and `as_text()`.** Case, host, observations, corroborating sources,
  alternative explanations, and a conclusion that never says "detected" and never says "confirmed".
- **False positive caught by the control:** identical process shapes across hosts are a standardised
  build, so similarity alone adds nothing; the test asserts the uncoupled case returns no edge.

## 2026-11-05 - THREAT-LENS

- **New: `lab/threatlens.py`.** Four analysers, one per threat class, because worms fail at
  propagation, trojans at execution and trust, commercial software at vendor trust, and ransomware at
  file access and recovery. No analyser takes a name, a hash, a signature or file contents.
- **Independence counted in telemetry sources.** The audit's finding about two signals on the same
  pixels applies here too: a write burst and a deleted shadow copy are both file metadata and count
  once. One source is `suspected`, two are `corroborated`, nothing is `confirmed`.
- **New: `lab/simulate_incident.py`.** Benign event generators for the four shapes plus an ordinary
  day, which is the false-positive control.
- **Fixed during the build:** sources were asserted per analyser instead of accruing per observation,
  so a fan-out-only stream reached `corroborated` on one log. Caught by a test that removes the
  service events. Autostart matching also only knew backslashes and missed a forward-slash path.

## 2026-11-05 - case 001: the museum feed

- **New: `lab/conceal.py`.** Counter-forensics as four checks: a clock that disagrees with the
  sealed record, provenance the pipeline wrote and the copy lost, container markers that say a tool
  wrote the file, and rows missing from a sealed manifest. The clock check had its direction
  backwards on the first run: sealing happens after writing, so an mtime earlier than the seal is
  the normal shape of an honest file. Fixed before it was pushed.
- **New: `scenario/museum.py`.** One case end to end: synthetic feed, injected clip, tampered
  manifest, refused operator, custody record. Emits `report.json` and `report.md` with a grade and
  a limitation per claim.
- **Change: `guard.write_manifest`.** The sealed writer was inline in `ingest`, so sealing a camera
  log meant pretending the rows were corpus records. Lifted out; `ingest` calls it.
- **The case proves the ceiling in public:** the event claim is `corroborated` with the custody log
  and `unknown` without it, from the same footage.

## 2026-11-05 - review round: the seal, the cap, and a finding I withdrew

- **L53 forensic integrity, S2.** `guard.verify` checked per-row HMACs and nothing else, so a
  deleted manifest line verified perfectly: a shorter manifest is as valid as a longer one. The
  manifest now ends with a sealed record carrying its row count and last signature, and a missing
  row fails verification. The regression test deletes a line and keeps the seal.
- **L15 input validation, S3.** Intake refused records past 1 MiB; verification parsed whatever it
  was handed. Same ceiling on both sides now.
- **L46 documentation, S4.** The README advertised 16 tests from two modules ago.

**Withdrawn:** I reported that `POST /cases/:id/exhibits` accepted an unchecked digest and wrote a
guard for it. The endpoint already rejected malformed digests, and my guard read the request body
before it was parsed, which returned 500 for every exhibit POST. The end-to-end job caught it and
the patch was reverted. The e2e assertion that a malformed digest gets a 400 stays.
