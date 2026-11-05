"""Command line: score one image, score a folder, or calibrate on reference images."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .calibrate import IMAGES, calibrate, score_image
from .report import assess, render


def _load(path: str | None) -> dict | None:
    return json.loads(Path(path).read_text(encoding="utf-8")) if path else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="seam", description="Look at the seam, not the picture.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    one = sub.add_parser("score", help="score one image")
    one.add_argument("image")
    one.add_argument("--calibration")
    one.add_argument("--json", action="store_true")

    many = sub.add_parser("batch", help="score every image in a folder")
    many.add_argument("folder")
    many.add_argument("--calibration")
    many.add_argument("--out", default="seam-report.json")

    cal = sub.add_parser("calibrate", help="derive thresholds from reference images")
    cal.add_argument("folder")
    cal.add_argument("--out", default="seam-calibration.json")

    args = parser.parse_args(argv)

    if args.cmd == "calibrate":
        result = calibrate(args.folder, args.out)
        print(json.dumps(result["stats"], indent=2))
        print(f"wrote {args.out}")
        return 0

    if args.cmd == "score":
        metrics = score_image(args.image)
        assessment = assess(metrics, _load(args.calibration))
        if args.json:
            print(json.dumps({"metrics": metrics, "assessment": assessment}, indent=2))
        else:
            print(render(metrics, assessment))
        return 0

    paths = sorted(p for p in Path(args.folder).rglob("*") if p.suffix.lower() in IMAGES)
    calibration = _load(args.calibration)
    rows = []
    for path in paths:
        metrics = score_image(str(path))
        assessment = assess(metrics, calibration)
        rows.append({"path": str(path), "metrics": metrics, "assessment": assessment})
        print(f"{assessment['hits']} tell(s)  {path}")
    Path(args.out).write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    print(f"{len(rows)} images -> {args.out}")
    return 0
