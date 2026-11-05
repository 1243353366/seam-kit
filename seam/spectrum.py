"""Radial spectrum.

Generative decoders upsample on a fixed stride and leave harmonics. So does JPEG, at 8 pixels,
which is the confound that makes this signal worth reporting and not worth trusting alone.
"""
from __future__ import annotations

import numpy as np

from .io import luma

JPEG_PERIOD = 8.0


def _radial_profile(y: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    h, w = y.shape
    window = np.outer(np.hanning(h), np.hanning(w))
    spec = np.abs(np.fft.fftshift(np.fft.fft2(y * window)))
    cy, cx = h // 2, w // 2
    yy, xx = np.indices((h, w))
    radius = np.hypot(yy - cy, xx - cx).astype(np.int32).ravel()
    max_radius = min(cy, cx)
    profile = np.bincount(radius, weights=spec.ravel(), minlength=max_radius + 1)[1 : max_radius + 1]
    counts = np.bincount(radius, minlength=max_radius + 1)[1 : max_radius + 1]
    return profile / np.maximum(counts, 1), np.arange(1, max_radius + 1)


def spectrum_metrics(arr: np.ndarray, min_period: float = 3.0, max_period: float = 64.0) -> dict:
    y = luma(arr)
    profile, radii = _radial_profile(y - y.mean())
    if profile.size < 8:
        return {"spectrum_period": 0.0, "spectrum_prominence": 0.0, "spectrum_near_jpeg": False}

    base = float(min(y.shape))
    periods = base / radii

    band = (periods >= min_period) & (periods <= max_period)
    if not band.any():
        return {"spectrum_period": 0.0, "spectrum_prominence": 0.0, "spectrum_near_jpeg": False}

    # The radial profile of any photograph falls off steeply with radius, so a peak measured
    # against the band's median level is really a measurement of that falloff. Detrend first:
    # divide by a smoothed copy of the same profile, then look for a bin that stands above its
    # own neighbourhood. Noise sits near 1.0; a harmonic does not.
    # A mean filter would eat the spike it is meant to measure, so the baseline is a median of
    # the neighbourhood *excluding* the bin under test. Noise sits near 1.0; a harmonic does not.
    baseline = np.empty_like(profile)
    for i in range(profile.size):
        left = profile[max(0, i - 9) : max(0, i - 3)]
        right = profile[i + 4 : i + 10]
        window = np.concatenate([left, right]) if left.size or right.size else profile
        baseline[i] = np.median(window)
    ratio = profile / np.maximum(baseline, 1e-12)
    idx = int(np.argmax(np.where(band, ratio, -np.inf)))
    prominence = float(ratio[idx])
    period = float(periods[idx])
    return {
        "spectrum_period": round(period, 2),
        "spectrum_prominence": round(prominence, 2),
        "spectrum_near_jpeg": bool(abs(period - JPEG_PERIOD) <= 0.6),
    }
