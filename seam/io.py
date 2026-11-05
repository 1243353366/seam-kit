"""Image loading, and the single place a JPEG round-trip is allowed to happen."""
from __future__ import annotations

import io

import numpy as np
from PIL import Image


def load_rgb(path: str) -> np.ndarray:
    with Image.open(path) as im:
        return np.asarray(im.convert("RGB"), dtype=np.uint8)


def jpeg_roundtrip(arr: np.ndarray, quality: int = 90) -> np.ndarray:
    """Compress and decompress in memory. 4:4:4 so chroma subsampling is not the diff."""
    buf = io.BytesIO()
    Image.fromarray(arr, mode="RGB").save(buf, format="JPEG", quality=quality, subsampling=0)
    buf.seek(0)
    with Image.open(buf) as im:
        return np.asarray(im.convert("RGB"), dtype=np.uint8)


def luma(arr: np.ndarray) -> np.ndarray:
    a = arr.astype(np.float32)
    return 0.299 * a[..., 0] + 0.587 * a[..., 1] + 0.114 * a[..., 2]


def block_means(values: np.ndarray, block: int) -> np.ndarray:
    h, w = values.shape
    bh, bw = h // block, w // block
    if bh == 0 or bw == 0:
        return np.array([float(values.mean())], dtype=np.float32)
    core = values[: bh * block, : bw * block].reshape(bh, block, bw, block)
    return core.mean(axis=(1, 3))
