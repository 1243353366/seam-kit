"""Noise residual.

A sensor leaves roughly white noise across the frame. A synthesised or pasted region is either
smoother than the rest or too evenly textured. Deviation in either direction counts, so the
ratio is compared against a calibrated reference and not against 1.0.
"""
from __future__ import annotations

import numpy as np

from .io import luma


def noise_metrics(arr: np.ndarray, inner: float = 0.5) -> dict:
    y = luma(arr)
    lap = np.abs(
        4 * y[1:-1, 1:-1] - y[:-2, 1:-1] - y[2:, 1:-1] - y[1:-1, :-2] - y[1:-1, 2:]
    )
    h, w = lap.shape
    my, mx = int(h * (1 - inner) / 2), int(w * (1 - inner) / 2)
    core = lap[my : h - my, mx : w - mx] if my or mx else lap
    return {
        "noise_ratio": round(float(core.std() / (lap.std() + 1e-6)), 4),
        "noise_lap_std": round(float(lap.std()), 4),
        "noise_inner": inner,
    }
