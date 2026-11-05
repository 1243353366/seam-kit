# Changelog

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
