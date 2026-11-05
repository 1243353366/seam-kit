"""The sample pair must still separate.

Two things could rot quietly: the composite stops showing a tell, or the untouched frame starts
showing one. Either makes every later number meaningless, so CI checks both directions instead
of just "it ran".
"""
from __future__ import annotations

import json
import sys


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)["assessment"]


def main(argv: list[str]) -> int:
    flagged, clean = load(argv[1]), load(argv[2])
    print(f"composite hits={flagged['hits']} clean hits={clean['hits']}")
    if flagged["hits"] < 1:
        print("the composite sample no longer shows a tell; the demo is lying", file=sys.stderr)
        return 1
    if clean["hits"] != 0:
        print("the untouched sample now trips a detector; thresholds or code drifted", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
