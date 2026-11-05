"""Calibration: score real images from the same camera, then set the limits from them.

Without this step every threshold here is a guess borrowed from someone else's images. The
report says so, and the CLI refuses to pretend otherwise.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from .ela import ela_metrics
from .io import load_rgb
from .noise import noise_metrics
from .spectrum import spectrum_metrics

IMAGES = {".png", ".jpg", ".jpeg", ".webp", ".bmp"}


def score_image(path: str) -> dict:
    arr = load_rgb(path)
    out = {"path": str(path), "width": int(arr.shape[1]), "height": int(arr.shape[0])}
    out.update(ela_metrics(arr))
    out.update(spectrum_metrics(arr))
    out.update(noise_metrics(arr))
    return out


def calibrate(folder: str, out_path: str | None = None) -> dict:
    paths = sorted(p for p in Path(folder).rglob("*") if p.suffix.lower() in IMAGES)
    if len(paths) < 3:
        raise SystemExit(f"{folder}: need at least 3 reference images, found {len(paths)}")
    rows = [score_image(str(p)) for p in paths]
    stats = {}
    for key in ("ela_ratio", "ela_hot_share", "noise_ratio", "spectrum_prominence"):
        values = np.array([r[key] for r in rows], dtype=np.float64)
        stats[key] = {
            "mean": round(float(values.mean()), 4),
            "sd": round(float(values.std(ddof=1)), 4) if len(values) > 1 else 0.0,
            "max": round(float(values.max()), 4),
        }
    result = {"reference_count": len(rows), "folder": str(folder), "stats": stats}
    if out_path:
        Path(out_path).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result
