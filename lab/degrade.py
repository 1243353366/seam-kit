"""The surveillance pipeline.

Both corpora go through exactly this, in the same order, with the same parameters. That is the
whole experimental contract: a difference between authentic and manipulated frames is only
interesting if it survives the processing that both of them share.
"""
from __future__ import annotations

import io

import numpy as np
from PIL import Image, ImageFilter

LEVELS: dict[str, dict] = {
    "clean": {},
    "q75": {"quality": 75},
    "q50": {"quality": 50},
    "cctv": {"quality": 50, "factor": 3, "radius": 1.0},
}


def jpeg(arr: np.ndarray, quality: int = 75) -> np.ndarray:
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, format="JPEG", quality=quality, subsampling=1)
    buf.seek(0)
    with Image.open(buf) as im:
        return np.asarray(im.convert("RGB"), dtype=np.uint8)


def rescale(arr: np.ndarray, factor: int = 3) -> np.ndarray:
    """Downscale then upscale: what a low-resolution camera and a player do between them."""
    im = Image.fromarray(arr)
    small = im.resize((max(8, im.width // factor), max(8, im.height // factor)), Image.BILINEAR)
    return np.asarray(small.resize(im.size, Image.BICUBIC), dtype=np.uint8)


def blur(arr: np.ndarray, radius: float = 1.0) -> np.ndarray:
    return np.asarray(Image.fromarray(arr).filter(ImageFilter.GaussianBlur(radius)), dtype=np.uint8)


def apply(arr: np.ndarray, level: str = "clean") -> np.ndarray:
    spec = LEVELS[level]
    out = arr
    if spec.get("factor"):
        out = rescale(out, spec["factor"])
    if spec.get("radius"):
        out = blur(out, spec["radius"])
    quality = spec.get("quality")
    if quality is not None:
        out = jpeg(out, quality)
    return out
