# seam-kit

Two tools that look at artifacts instead of claims.

- **seam** — three weak forensic signals for manipulated images, with calibration and a report that
  counts how many of them agree instead of printing a verdict.
- **guard** — corpus intake that quarantines with a reason attached and writes an HMAC manifest you
  can check next month.

## The lab (polyglot)

`lab/` is Python and measures. `api/` is TypeScript on Node 24 and stores. `db/`-free: the store is
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
- No video and no audio yet. Frame jitter and lip-band flicker are the next signals worth adding,
  and they need a sequence, not a still.
- In the guard, label arbitration trusts the majority of a cluster. A flood bigger than your honest
  copies flips it, so read `clusters` and `largest_cluster` before you trust a run.

## Tests

```sh
python -m unittest discover -s tests -q     # 16 tests
```

The forensic tests build frames with a known answer (a quantised patch, a raw patch, a periodic
grid at 8 and at 16 px) and assert the detectors respond to the right thing. The guard tests assert
the record: a flood is quarantined with a reason, an edited manifest fails, a missing key is refused
rather than defaulted.
