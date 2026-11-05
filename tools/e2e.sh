#!/usr/bin/env bash
# Python computes, Node stores. This is the seam between them, so it also tests whether the case
# store keeps what the lab measured, and whether it notices when a row is edited afterwards.
set -euo pipefail
cd "$(dirname "$0")/.."

export PORT="${PORT:-8899}"
TMP="$(mktemp -d)"
export SEAM_DB="$TMP/seam.db"

node api/src/server.ts &
PID=$!
trap 'kill "$PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 60); do
  curl -sf "http://127.0.0.1:$PORT/health" >/dev/null && break
  sleep 0.1
done

curl -sf -X POST "http://127.0.0.1:$PORT/cases" -d '{"id":"case-1","label":"lupin-drill"}' >/dev/null

SHA="$(python3 -c "import hashlib;print(hashlib.sha256(open('demo/composite.png','rb').read()).hexdigest())")"
curl -sf -X POST "http://127.0.0.1:$PORT/cases/case-1/exhibits" -d "{\"sha256\":\"$SHA\",\"note\":\"composite\"}" >/dev/null
curl -sf -X POST "http://127.0.0.1:$PORT/exhibits/1/runs" -d '{"level":"cctv","signals":{"noise_ratio":0.71,"seam_edge":1.02,"chroma_step":1.3,"block_grid":0.9}}' >/dev/null

python3 - "$PORT" <<'PYEOF'
import json
import sys
import urllib.request

port = sys.argv[1]

def get(path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:
        return json.load(r)

chain = get("/cases/case-1/chain")
assert chain["ok"] is True, chain
assert chain["exhibit_count"] == 1, chain
runs = get("/runs?exhibit=1")["runs"]
assert runs and runs[0]["level"] == "cctv", runs

# Now edit the exhibit behind the store's back and ask again: the chain must notice.
import sqlite3

db = sqlite3.connect(__import__("os").environ["SEAM_DB"])
db.execute("update exhibits set note = 'quietly rewritten' where id = 1")
db.commit()
db.close()

after = get("/cases/case-1/chain")
assert after["ok"] is False, after
print("e2e ok: chain verified, then caught the edit")
PYEOF
