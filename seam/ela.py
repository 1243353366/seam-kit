"""Error level analysis.

Recompress at a known quality and diff. A region that has been through a different number of
JPEG generations answers differently from its surroundings: a patch pasted in from a JPEG is
*cold*, because it has already been quantised, while untouched pixels are *hot*.

That direction matters and is the thing most ELA write-ups get wrong. On a source that has
already been compressed once, every block errors by roughly the same amount and the signal is
gone, which is why this never decides a verdict on its own.
"""
from __future__ import annotations

import numpy as np

from .io import block_means, jpeg_roundtrip, luma

#: Below this median block error the frame is either flat or already fully quantised, and a
#: ratio computed from it is division by nothing.
QUIET_MEDIAN = 0.30


def ela_metrics(arr: np.ndarray, quality: int = 90, block: int = 16) -> dict:
    rt = jpeg_roundtrip(arr, quality)
    diff = np.abs(luma(arr) - luma(rt))
    blocks = block_means(diff, block)
    median = float(np.median(blocks))
    quiet = median < QUIET_MEDIAN
    floor = max(median, QUIET_MEDIAN)
    return {
        "ela_ratio": round(float(np.percentile(blocks, 99)) / floor, 3),
        "ela_hot_share": round(float((blocks > 4 * floor).mean()), 4),
        "ela_cold_share": round(float((blocks < 0.25 * floor).mean()), 4) if not quiet else 0.0,
        "ela_median": round(median, 4),
        "ela_quiet": bool(quiet),
        "ela_block": block,
        "ela_quality": quality,
    }
