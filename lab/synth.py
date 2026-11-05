"""Controlled synthetic material.

This is deliberately not a deepfake generator. It is a stand-in whose seams we control, so a
signal can be scored against a known answer: we know where the region is, we know it was
replaced, and we know how it was blended. Whether a real generator leaves the same seam is a
separate question, and one this kit cannot answer without real samples.
"""
from __future__ import annotations

import numpy as np
from PIL import Image, ImageFilter


def rng(seed: int) -> np.random.Generator:
    return np.random.default_rng(seed)


def _grid(size: int):
    return np.mgrid[0:size, 0:size]


def face_region(size: int):
    """The oval a portrait's face would occupy, plus the ellipse parameters."""
    y, x = _grid(size)
    cx, cy, ax, ay = size / 2, size * 0.55, size * 0.22, size * 0.28
    return ((((x - cx) / ax) ** 2 + ((y - cy) / ay) ** 2) <= 1), (cx, cy, ax, ay)


def face_frame(seed: int = 0, size: int = 256) -> np.ndarray:
    """A plausible portrait: textured background, skin oval, eyes, mouth, sensor noise."""
    r = rng(seed)
    y, x = _grid(size)
    bg = 60 + 40 * np.sin(x / (17 + seed % 7)) + 30 * np.cos(y / (23 + seed % 5))
    img = np.dstack([bg, bg * 0.95, bg * 0.9]).astype(np.float32)

    oval, (cx, cy, ax, ay) = face_region(size)
    skin = np.array([205 + (seed % 11), 165 + (seed % 7), 140 + (seed % 5)], dtype=np.float32)
    img[oval] = skin
    img[oval] *= (1.0 - 0.25 * ((x[oval] - cx) ** 2) / (2 * ax ** 2))[:, None]

    for sx in (-1, 1):
        ex, ey = cx + sx * ax * 0.45, cy - ay * 0.35
        eye = (((x - ex) ** 2) / 100 + ((y - ey) ** 2) / 36) <= 1
        img[eye] = [40, 40, 45]
    mouth = (np.abs(y - (cy + ay * 0.45)) < 4) & (np.abs(x - cx) < ax * 0.35)
    img[mouth] = [120, 70, 75]

    img += r.normal(0, 4.0, img.shape)
    return np.clip(img, 0, 255).astype(np.uint8)


def manipulate(img: np.ndarray, seed: int = 1, feather: int = 1) -> np.ndarray:
    """Replace the face with a different, over-smooth donor and blend the boundary.

    The over-smoothing is the honest part: generative output loses sensor noise. The narrow
    feather is what a compositor does to hide a seam, so the resulting edge is real but small.
    """
    size = img.shape[0]
    out = img.astype(np.float32).copy()
    oval, _ = face_region(size)
    donor = face_frame(seed=seed + 1000, size=size)
    smooth = np.asarray(Image.fromarray(donor).filter(ImageFilter.GaussianBlur(2.2))).astype(np.float32)

    weight = oval.astype(np.float32)
    if feather > 0:
        weight = np.asarray(
            Image.fromarray((weight * 255).astype(np.uint8)).filter(ImageFilter.GaussianBlur(feather))
        ).astype(np.float32) / 255.0
        weight = np.clip(weight, 0.0, 1.0)
    w = weight[:, :, None]
    return np.clip(out * (1 - w) + smooth * w, 0, 255).astype(np.uint8)
