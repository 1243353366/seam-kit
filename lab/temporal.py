"""Temporal signals: the part a single frame cannot show.

A video is a set of claims about the same face over time, and the failures that matter are the
ones that only exist between frames: texture that flickers, an identity that drifts as the head
turns, a cut where motion should be.

Three measurements, each of which is weaker than it sounds:

  flicker  high-pass energy that appears and vanishes between consecutive frames
  drift    how far each frame's face-region appearance sits from the sequence's own median
  cut      a frame-to-frame discontinuity too large to be motion

Orientation: higher means more suspicious for all three, so they share a threshold story. None of
them establishes synthesis. A dropped frame, a strobe light and a re-encode all move them.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import numpy as np

REGION_FRACTION = 0.22  # half-width of the oval, as a fraction of frame width


def load_video(path: str, size: int = 128, max_frames: int = 120) -> np.ndarray:
    """Decode a file to (T, H, W, 3) uint8 through ffmpeg, or raise if ffmpeg is absent."""
    if shutil.which("ffmpeg") is None:
        raise RuntimeError("ffmpeg not found")
    with tempfile.TemporaryDirectory() as tmp:
        raw = Path(tmp) / "frames.rgb"
        subprocess.run(
            ["ffmpeg", "-v", "error", "-i", str(path), "-vf", f"scale={size}:{size}",
             "-pix_fmt", "rgb24", "-frames:v", str(max_frames), "-f", "rawvideo", str(raw)],
            check=True,
        )
        data = np.frombuffer(raw.read_bytes(), dtype=np.uint8)
    if data.size == 0:
        raise RuntimeError("no frames decoded")
    per = size * size * 3
    count = data.size // per
    return data[: count * per].reshape(count, size, size, 3)


def write_video(frames: np.ndarray, path: str, fps: int = 12) -> str:
    """Write (T, H, W, 3) uint8 to an H.264 mp4. Used by tests and the demo."""
    if shutil.which("ffmpeg") is None:
        raise RuntimeError("ffmpeg not found")
    t, h, w, _ = frames.shape
    with tempfile.TemporaryDirectory() as tmp:
        proc = subprocess.Popen(
            ["ffmpeg", "-v", "error", "-y", "-f", "rawvideo", "-pix_fmt", "rgb24",
             "-s", f"{w}x{h}", "-r", str(fps), "-i", "pipe:0",
             "-c:v", "libx264", "-pix_fmt", "yuv420p", str(path)],
            stdin=subprocess.PIPE,
        )
        proc.communicate(frames.astype(np.uint8).tobytes())
        if proc.returncode != 0:
            raise RuntimeError("ffmpeg failed to encode")
    return path


def _luma(frame: np.ndarray) -> np.ndarray:
    a = frame.astype(np.float32)
    return 0.299 * a[..., 0] + 0.587 * a[..., 1] + 0.114 * a[..., 2]


def _region(shape: tuple[int, int]) -> np.ndarray:
    h, w = shape
    y, x = np.mgrid[0:h, 0:w]
    return (((x - w / 2) / (w * REGION_FRACTION)) ** 2
            + ((y - h * 0.55) / (h * REGION_FRACTION * 1.25)) ** 2) <= 1.0


def _lap(y: np.ndarray) -> np.ndarray:
    return np.abs(4 * y[1:-1, 1:-1] - y[:-2, 1:-1] - y[2:, 1:-1] - y[1:-1, :-2] - y[1:-1, 2:])


def flicker(frames: np.ndarray) -> float:
    """How much the face region's brightness and texture swing across the sequence.

    Measured as the peak-to-peak swing over the median, not as frame-to-frame differences: an
    alternating pulse has a large change on *every* step, so a ratio of deltas reports it as
    perfectly stable. The swing is what a viewer sees.
    """
    if len(frames) < 2:
        return 0.0
    region = _region(frames.shape[1:3])
    # _lap already shrinks by one pixel on each side, so the region is cropped to match, once.
    highs = np.array([float(_lap(_luma(f))[region[1:-1, 1:-1]].mean()) for f in frames])
    lumas = np.array([float(_luma(f)[region].mean()) for f in frames])

    def swing(values: np.ndarray) -> float:
        level = float(np.median(values)) or 1e-6
        return float((values.max() - values.min()) / level)

    return max(swing(highs), swing(lumas))


def drift(frames: np.ndarray) -> float:
    """How far the face region's appearance moves from the sequence's own median frame.

    Colour histograms say "skin is skin" for any face, so identity is read from the arrangement:
    the region's bounding box is reduced to a 16x16 grayscale grid and compared as a vector.
    """
    if len(frames) == 0:
        return 0.0
    region = _region(frames.shape[1:3])
    ys, xs = np.where(region)
    y0, y1, x0, x1 = int(ys.min()), int(ys.max()) + 1, int(xs.min()), int(xs.max()) + 1
    vectors = []
    for f in frames:
        crop = _luma(f)[y0:y1, x0:x1]
        step = max(1, min(crop.shape) // 16)
        hh, ww = (crop.shape[0] // step) * step, (crop.shape[1] // step) * step
        grid = crop[:hh, :ww].reshape(hh // step, step, ww // step, step).mean(axis=(1, 3))
        vectors.append(np.asarray(grid, dtype=np.float64).reshape(-1))
    stack = np.array([v - v.mean() for v in vectors])  # brightness is flicker's business
    med = np.median(stack, axis=0)
    denom = (np.linalg.norm(stack, axis=1) * np.linalg.norm(med)) + 1e-9
    return float((1.0 - (stack @ med) / denom).max())


def cut(frames: np.ndarray) -> float:
    """Largest frame-to-frame change, measured against the sequence's typical change."""
    if len(frames) < 2:
        return 1.0
    lum = np.array([_luma(f) for f in frames])
    diffs = np.abs(np.diff(lum, axis=0)).mean(axis=(1, 2))
    typical = float(np.median(diffs)) or 1e-6
    return float(diffs.max() / typical)


def analyse(frames: np.ndarray) -> dict:
    return {
        "frames": int(len(frames)),
        "flicker": round(flicker(frames), 3),
        "drift": round(drift(frames), 3),
        "cut": round(cut(frames), 3),
    }


def main(argv: list[str] | None = None) -> int:
    import sys

    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print("usage: python -m lab.temporal <video>")
        return 2
    print(json.dumps(analyse(load_video(args[0])), indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
