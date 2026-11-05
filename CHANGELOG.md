# Changelog

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
