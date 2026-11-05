"""Two synthetic frames with a known answer, so the first run shows a real difference."""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from seam.io import jpeg_roundtrip  # noqa: E402

OUT = Path(__file__).parent


def photo(seed: int = 3, size: int = 320) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return rng.normal(118, 16, (size, size, 3)).clip(0, 255).astype(np.uint8)


def main() -> None:
    clean = photo()
    Image.fromarray(clean).save(OUT / "untouched.png")

    # A patch that arrived already quantised, pasted into an untouched frame.
    comp = clean.copy()
    comp[40:200, 40:200] = jpeg_roundtrip(clean[40:200, 40:200], quality=50)
    Image.fromarray(comp).save(OUT / "composite.png")
    print(f"wrote {OUT/'untouched.png'} and {OUT/'composite.png'}")


if __name__ == "__main__":
    main()
