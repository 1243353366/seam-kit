# seam-kit

Two tools that look at artifacts instead of claims.

- **seam** — three weak forensic signals for manipulated images, with calibration and a report that
  counts how many of them agree instead of printing a verdict.
- **guard** — corpus intake that quarantines with a reason attached and writes an HMAC manifest you
  can check next month.

## Why this exists: Lupin, Part 4

The show's premise is the problem this repository is built around. In Part 4 a hacker impersonates
Assane and fabricates surveillance footage placing him at crimes he did not commit, while he is
physically somewhere else, and the footage does the accusing. Netflix's published material
confirms the techniques at the level of plot: synthetic footage used to incriminate him, drones
and holograms in the operations, a hacker doing the work. It does not disclose how any of it is
implemented, and nothing here claims to reconstruct that.

What carried over is the question the plot makes unavoidable. A camera says the man was at the
museum at 14:07. A custody log says he was in a cell at 14:00. Something has to decide which of
those wins, and it cannot be "whatever the pixels look like", because the pixels are the thing
under attack.

Three commitments come straight out of that scenario:

- **No footage is a verdict.** The signals produce a grade, the basis for it, and the limitations
  that stop it from being more. A confident number with no stated ceiling is the failure mode the
  plot depends on.
- **Independent records outrank media.** `lab/adjudicate.py` caps the claim "this event did not
  happen" at `unknown` no matter how synthetic the footage looks. It rises only when a source that
  is not the footage contradicts the event. That is the custody log, not a better detector.
- **The concealment is the evidence.** In the show the operation succeeds by controlling the
  camera, the record and the clock, not by rendering a perfect face. So `lab/conceal.py` asks what
  a concealment cannot remove: a sealed count, a recorded time, a container that names its writer.

Case 001 in [docs/case-museum.md](docs/case-museum.md) is that scenario built from synthetic
parts, so every claim above can be checked by running `make case` rather than taken on trust.

## The lab (polyglot)

The first complete case is in [docs/case-museum.md](docs/case-museum.md). Modules and their
method notes are in [docs/lab-identity.md](docs/lab-identity.md),
[docs/lab-graph.md](docs/lab-graph.md) and [docs/lab-adjudicate.md](docs/lab-adjudicate.md).
Host behaviour for four threat classes, with independence counted in telemetry sources rather
than observations, is in [docs/threat-lens.md](docs/threat-lens.md).
What an intrusion record has to contain, read off CISA's playbook and Europol's 2025
paper rather than recalled, is in [docs/intrusion-model.md](docs/intrusion-model.md). How the external audit's ten findings were
triaged, including the two I think describe a boundary rather than a defect, is in
[docs/audit-response.md](docs/audit-response.md).

`lab/` is Python and measures (signals, correlation, binary analysis). `api/` is TypeScript on Node 24 and stores. `db/`-free: the store is
SQLite through `node:sqlite`, with an append-only exhibit chain where each link hashes its
predecessor.

```sh
make test     # python tests, then the case store's tests
make lab      # the experiment, writing docs/lab-report.md
make e2e      # python computes, node stores, then the chain is quietly edited and must notice
make api      # the store on 127.0.0.1:8787
```

The experiment answers one question and refuses to answer a second. It asks: after both corpora
pass through the same surveillance pipeline, which signals still separate them? It refuses to
claim that a signal identifies a deepfake, because on this corpus two of the four are measuring
the blur the generator applied rather than the manipulation.

Headline result at `cctv` degradation: `noise_ratio` survives, `seam_edge` flips polarity between
levels so its threshold does not transfer, `chroma_step` collapses, and `block_grid` is a
compression witness that dies at the harshest level. Full table and method in
[`docs/lab.md`](docs/lab.md).

## What this does not do

No poisoned-corpus mode and no steganographic payload. Poisoned rows do not protect a corpus
(any scraper filtering for quality discards them), they destroy the record you would need later,
since a corpus you deliberately falsified cannot show which copies were yours, and they escalate
into something indistinguishable from the attack being described. `guard` writes canary tags and
an HMAC manifest instead: attributable, and checkable months later by someone who was not there.

No video yet. The still-image signals port to frames; per-frame residual jitter and lip-band
flicker are a separate pass and are not written here.

## Start

```sh
unzip seam-kit.zip && cd seam-kit
./launch.sh
```

If the browser silently refuses the download, take it with curl instead:

```sh
curl -O <the-url> && unzip seam-kit.zip
```

`launch.sh` builds a local venv, runs the test suite, generates two sample frames and scores one.
Nothing is installed system-wide and nothing phones home.

## seam

```sh
python -m seam score photo.png            # one image, readable
python -m seam score photo.png --json     # same numbers, machine readable
python -m seam batch photos/ --out r.json # a folder, one report
python -m seam calibrate my_photos/       # thresholds from your own camera
```

Three signals, each deliberately dumb and independent:

| signal | what it sees | how it lies |
| --- | --- | --- |
| `ela` | recompress at q90 and diff per 16 px block. A patch pasted from a JPEG is **cold** (already quantised); a patch pasted raw is **hot** | silent on sources that are already fully quantised, and on flat areas |
| `spectrum` | radial FFT profile, detrended, looking for a periodic peak | an 8 px peak is JPEG blocking, not a generator. The report says so rather than scoring it |
| `noise` | Laplacian residual in the frame's core against the whole | deviation either way counts, so it needs a reference; without calibration it uses a guess |

The report prints how many tells agree, and refuses to call a quiet result authentic:

> one tell is noise. two is worth a second look. three is a pattern. none of it is proof, and a
> fake can be built to pass all three.

Calibrate before you believe a number. `calibrate` scores reference images from the same camera and
derives limits from them; every report states whether it was calibrated or is running on inherited
guesses.

## guard

```sh
export SEAM_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"

python -m guard ingest \
  --in incoming.jsonl --clean clean.jsonl \
  --quarantine quarantine.jsonl --manifest manifest.jsonl \
  [--seed trusted.jsonl]

python -m guard verify --manifest manifest.jsonl
```

What it does, in order: exact-duplicate collapse, near-duplicate clustering (shingled MinHash, 8x8
LSH), label arbitration inside a cluster, an optional seed-set audit, then a decision per row with
the reason written down. Suspect rows go to a quarantine file. **Nothing is deleted and nothing is
altered**, because a row you cannot inspect is a row you cannot defend.

Every row gets a canary tag derived from your key, and every row is HMAC'd into the manifest. Edit
one line of the manifest and `verify` says `TAMPERED`, which a plain hash could not do: the HMAC
means an attacker cannot simply recompute it.

## What this deliberately does not do

There is no poisoned-corpus mode here. The kit quarantines bad input and tags good output; it does
not fabricate rows designed to corrupt whoever ingests them. Three reasons, in order of how much
they matter:

1. **It does not protect you.** A scraper that filters for text quality drops the noise. One that
   does not still receives your real rows alongside it.
2. **It destroys the thing you would need.** If your corpus is deliberately wrong, you cannot later
   show which copies were yours and which were lies. A canary is a receipt. A lie is a liability,
   and you would be handing it to anyone who wants to argue the model was poisoned by you.
3. **It escalates.** Contaminating someone else's training pipeline is an attack on their system,
   and it is indistinguishable from the attack you are complaining about. If a specific model was
   trained on your work, the durable route is notice, licence and watermark, which produce evidence
   rather than a fight.

Same reasoning for images: no steganographic payload layer. If you need to prove an asset was
lifted, embed provenance you can read back (C2PA-style metadata, an invisible watermark) rather than
bait you cannot prove anyone ate.

## Honest limits

- One image is not a case. Three agreeing signals raise the odds; they do not close the question.
- Thresholds are guesses until `calibrate` runs on images from the same source.
- Manipulation that respects the seam (a full re-encode, a global resample) defeats all three.
- Generative artifacts move as the models do, so a detector tuned today is folklore in a year.
- Video is read (`lab/temporal.py`: drift, flicker, cut) but audio is not. Lip-band flicker needs
  waveform alignment against the frames, which is not built.
- Writes to the local store are unauthenticated. It binds to loopback and nothing more.
- **Authentication is not operation.** `lab/identity.py` can show who presented a credential. Nothing
  here can show who actually acted. Europol's 2025 paper on cybercrime disruption notes that initial
  access is bought and sold ("Initial Access Brokers are increasingly advertising these services"),
  so a credential that verifies may belong to whoever purchased it, not to the subject named in it.
  A successful authentication raises no claim about operation above `unknown`, and the museum case
  reports it that way on purpose.
- In the guard, label arbitration trusts the majority of a cluster. A flood bigger than your honest
  copies flips it, so read `clusters` and `largest_cluster` before you trust a run.

## Tests

```sh
python -m unittest discover -s tests -q     # 72 tests
```

The forensic tests build frames with a known answer (a quantised patch, a raw patch, a periodic
grid at 8 and at 16 px) and assert the detectors respond to the right thing. The guard tests assert
the record: a flood is quarantined with a reason, an edited manifest fails, a missing key is refused
rather than defaulted.
