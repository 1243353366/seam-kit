"""Five measurements, each of which is weaker than it sounds.

Every one of these is a ratio that a compositor, a compressor or a camera can move. They are
computed against a ground-truth region because this is a controlled study, not a detector: the
lab knows where the face is. Nothing here should be shipped as "deepfake detection" without the
FP and FN rates the experiment prints beside it.
"""
from __future__ import annotations

import numpy as np

from lab.synth import face_region
from seam.io import luma


def _lap(y: np.ndarray) -> np.ndarray:
    return np.abs(4 * y[1:-1, 1:-1] - y[:-2, 1:-1] - y[2:, 1:-1] - y[1:-1, :-2] - y[1:-1, 2:])


def _erode(mask: np.ndarray) -> np.ndarray:
    m = mask.copy()
    m[1:-1, 1:-1] = (
        mask[1:-1, 1:-1] & mask[:-2, 1:-1] & mask[2:, 1:-1] & mask[1:-1, :-2] & mask[1:-1, 2:]
    )
    return m


def _dilate(mask: np.ndarray) -> np.ndarray:
    m = mask.copy()
    m[1:-1, 1:-1] = (
        mask[1:-1, 1:-1] | mask[:-2, 1:-1] | mask[2:, 1:-1] | mask[1:-1, :-2] | mask[1:-1, 2:]
    )
    return m


def _halo(mask: np.ndarray, width: int = 4) -> np.ndarray:
    outer = mask.copy()
    for _ in range(width):
        outer = _dilate(outer)
    return outer & ~mask


def _ring(mask: np.ndarray, width: int = 3) -> np.ndarray:
    inner = mask.copy()
    for _ in range(width):
        inner = _erode(inner)
    return mask & ~inner


def noise_ratio(arr: np.ndarray) -> float:
    """Residual energy inside the region divided by the surrounding frame.

    Generative regions are too smooth: they lose the sensor noise. A frame that has been
    blurred by the pipeline compresses this ratio towards 1, which is the point of measuring it.
    """
    y = luma(arr)
    lap = _lap(y)
    mask = face_region(y.shape[0])[0][1:-1, 1:-1]
    inside = float(lap[mask].std()) if mask.any() else 0.0
    outside = float(lap[~mask].std()) or 1e-6
    return inside / outside


def seam_edge(arr: np.ndarray) -> float:
    """Gradient energy on the region boundary over gradient energy just outside it."""
    y = luma(arr)
    gy, gx = np.gradient(y)
    grad = np.hypot(gx, gy)
    mask = face_region(y.shape[0])[0]
    ring = _ring(mask, width=2)
    # The comparison band has to be the ring's neighbourhood, not the frame border: the first
    # version measured the image edge and returned a constant.
    halo = _halo(mask, width=4)
    if not ring.any() or not halo.any():
        return 1.0
    return float(grad[ring].mean()) / (float(grad[halo].mean()) or 1e-6)


def chroma_step(arr: np.ndarray) -> float:
    """Colour discontinuity across the boundary. Blending in Y only leaves a chroma edge."""
    f = arr.astype(np.float32)
    cb = -0.169 * f[:, :, 0] - 0.331 * f[:, :, 1] + 0.5 * f[:, :, 2]
    cr = 0.5 * f[:, :, 0] - 0.419 * f[:, :, 1] - 0.081 * f[:, :, 2]
    gm = np.hypot(*np.gradient(cb)) + np.hypot(*np.gradient(cr))
    mask = face_region(arr.shape[0])[0]
    ring = _ring(mask, width=2)
    inside = _erode(_erode(_erode(mask)))
    if not ring.any() or not inside.any():
        return 1.0
    return float(gm[ring].mean()) / (float(gm[inside].mean()) or 1e-6)


def block_grid(arr: np.ndarray) -> float:
    """Energy locked to an 8 pixel grid.

    This is a pipeline witness, not a manipulation signal: it says the frame has been through a
    JPEG encoder, which is true of both corpora here. Included so the report can show which
    signals are really detecting compression.
    """
    y = luma(arr)
    col = np.abs(np.diff(y, axis=1)).mean(axis=0)
    row = np.abs(np.diff(y, axis=0)).mean(axis=1)
    if col.size < 16 or row.size < 16:
        return 0.0
    peaks = (col[7::8].mean() if col[7::8].size else 0.0) + (row[7::8].mean() if row[7::8].size else 0.0)
    base = (col.mean() + row.mean()) or 1e-6
    return float(peaks / (2 * base))


#: Which way the signal points. A smoother fake means a *lower* residual ratio, and a report
#: that ignores direction scores a perfect separator as 0.0 AUC and files it as broken.
DIRECTION = {
    "noise_ratio": "lower",
    "seam_edge": "higher",
    "chroma_step": "higher",
    "block_grid": "higher",
}


def oriented(name: str, value: float) -> float:
    return -value if DIRECTION.get(name, "higher") == "lower" else value


def all_signals(arr: np.ndarray) -> dict[str, float]:
    return {
        "noise_ratio": round(noise_ratio(arr), 4),
        "seam_edge": round(seam_edge(arr), 4),
        "chroma_step": round(chroma_step(arr), 4),
        "block_grid": round(block_grid(arr), 4),
    }
