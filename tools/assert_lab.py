"""CI asserts the experiment still separates something, and still admits when it does not."""
from __future__ import annotations

import json
import pathlib
import sys

data = json.loads(pathlib.Path("docs/lab-result.json").read_text())
levels = data["levels"]
strongest = max(levels, key=lambda lvl: max(v["auc"] for v in levels[lvl].values()))
best = max(levels[strongest].items(), key=lambda kv: kv[1]["auc"])
worst = min(levels["cctv"].items(), key=lambda kv: kv[1]["auc"])

print(f"strongest {strongest}: {best[0]} auc={best[1]['auc']}")
print(f"weakest at cctv: {worst[0]} auc={worst[1]['auc']}")

if data["null_control"]["mean_auc"] > 0.6:
    sys.exit("null control drifted: shuffled labels are separating, which means a leak")

if best[1]["auc"] < 0.6:
    sys.exit("no signal separates the corpora any more; the report is not describing anything")
