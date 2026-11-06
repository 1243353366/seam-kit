# Response to the external audit

An external review of this repository produced ten findings and a remediation order. This is what
happened to each, with the evidence, including the two places I think the audit is describing a
boundary rather than a defect.

Triage legend: **fixed** means the code changed and a regression test fails before the change,
**open** means accepted and scheduled, **scope** means the reviewer's premise is wrong or the
finding describes a deliberate boundary.

| # | Finding | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Exhibit chain does not cover runs, actor, tool version, timestamps, and is not anchored externally | open | `api/src/server.ts`: the link hashes `prev + sha256 + note`; `runs` is a separate table |
| 2 | Adjudicator can overstate conclusions | **fixed** | `lab/adjudicate.py` |
| 3 | Validation does not establish real detection | accepted, open | `lab/experiment.py`: holdout families differ by blur parameter only, and the operating point is chosen on the rows it is then scored on |
| 4 | Temporal analysis truncates and uses a fixed region | partially fixed | `lab/temporal.py`: `max_frames=120`, 128x128, fixed oval |
| 5 | Concealment checks conflate processing with intent | **fixed** | `lab/conceal.py`: three categories |
| 6 | GUARD size limit applied after loading | **fixed** | `guard/ingest.py`: `_read_lines` |
| 7 | Short identifiers | **fixed** | 128-bit record and canary identifiers |
| 8 | Identity is a simulator | scope | documented as a model since it was written; revocation and nonce lifecycle are open |
| 9 | Local API has no authentication | open, high | loopback binding only |
| 10 | Examination records outside the integrity chain | open | same code as finding 1 |

## What changed this pass

**Finding 2, the one that mattered most.** The adjudicator could reach `confirmed` from two agreeing
signals plus a provenance flag. Three claims were wrong in that. A count of signals measured on the
same pixels is not evidence fusion; `insertion_evidence` is a field somebody asserted and this layer
cannot check; and `calibration` produced a caveat instead of determining the grade. Now: this layer
never returns `confirmed`, agreement above `suspected` requires measured operating points, provenance
adds a basis line and promotes nothing, and the returned block records whether it was calibrated.

The same pass fixed a second error the audit did not name, in `event_claim`: it required the media
grade to be `corroborated` before an independent record could contradict the event. That made a
custody log less credible whenever the pixels were ambiguous. A record does not need the footage's
permission, and the media grade is now context rather than a gate. The museum case reports
`media: suspected` and `event: corroborated`, which is the honest pair.

**Findings 5, 6, 7.** Concealment findings carry one of three categories now, so an encoder tag is an
observed alteration, a backdated file is an inconsistency with a record kept elsewhere, and missing
metadata is only ever a possible concealment indicator. GUARD reads line by line and refuses the
file on an over-long line or on a record flood, where it used to skip and fail open, and the manifest
is written to a temp file, fsynced and renamed. Identifiers went from 64 and 48 bits to 128.

Regression tests added: `test_provenance_cannot_promote_a_grade`, `test_nothing_here_is_ever_confirmed`,
`test_agreement_without_calibration_is_capped_at_suspected`,
`test_an_independent_source_stands_on_its_own`, `test_a_record_too_large_to_parse_refuses_the_file`,
`test_a_record_flood_is_refused_rather_than_absorbed`,
`test_the_manifest_is_written_whole_or_not_at_all`,
`test_media_stays_at_suspected_without_measured_thresholds`.

## Where I think the audit is describing a boundary

**"The API accepts a SHA-256 string supplied by the client."** True, and deliberate: this store
records digests computed by an examiner's tooling and never receives evidence files. The finding I
accept is narrower and still real: nothing documents that boundary or checks that the digest was
computed from a file at all, so the API cannot be used as evidence of anything on its own. It belongs
in the API's own documentation before it belongs in the code.

**"Identity is a simulator."** It is labelled one, in the module and in the README. The useful part
of the finding is the inventory of what a real system needs, which is now recorded rather than
disputed.

## Order of work, with acceptance criteria

1. **Evidence ledger (findings 1 and 10).** Every event gets id, case, exhibit, type, previous hash,
   timestamp, actor, input and output hashes, tool version, configuration hash and result hash; runs
   join the chain; a signed checkpoint is anchored outside the database. *Acceptance:* mutate a run
   result, backdate an event, delete the last event, then rewrite the whole SQLite file. Each
   alteration must be detectable against the retained checkpoint.
2. **Locked evaluation (finding 3).** Development, calibration and locked evaluation, with the locked
   set held out of threshold selection and containing footage not produced by `lab/synth.py`.
   *Acceptance:* a second person can reproduce the reported false-positive and false-negative rates
   without access to training or calibration labels.
3. **Full-duration examination (finding 4).** Face tracking in place of the fixed oval, sampling
   across the whole duration, and explicit coverage in every report. *Acceptance:* a manipulation
   placed at 80 percent of a ten-minute video is examined, and the report states which frames were
   and were not.
4. **Store authentication (finding 9).** Token on write routes, origin checks, audit log of
   administrative operations, loopback binding kept. *Acceptance:* an unauthenticated write returns
   401 and appears in the audit log as refused.
5. **Reproducible builds.** Hashed lockfiles, actions pinned to commit SHAs, recorded environment
   manifest. *Acceptance:* a clean checkout produces byte-identical artifacts and a CI run that
   records the resolved hashes.

The audit's summary line is the one I would keep: the weakness is not that the detectors are simple,
it is the distance between an observation and the conclusion the system permits. That distance is
what items 1 and 2 close.
