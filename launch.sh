#!/usr/bin/env bash
# Sets up and proves the kit works, without touching your system python.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
. .venv/bin/activate
pip install -q --disable-pip-version-check -r requirements.txt

echo "== tests =="
python -m unittest discover -s tests -q

echo "== sample =="
python demo/make_samples.py
python -m seam score demo/composite.png

cat <<'USE'

Ready. Useful commands:

  python -m seam score path/to/image.png          one image, human readable
  python -m seam score path/to/image.png --json   machine readable
  python -m seam batch path/to/folder             every image, one JSON report
  python -m seam calibrate path/to/real/photos    set thresholds from your own camera

  export SEAM_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
  python -m guard ingest --in corpus.jsonl --clean clean.jsonl \
      --quarantine quarantine.jsonl --manifest manifest.jsonl [--seed seeds.jsonl]
  python -m guard verify --manifest manifest.jsonl
USE
