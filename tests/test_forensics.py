"""Synthetic cases with a known answer, so the detectors are tested against something true."""
from __future__ import annotations

import unittest

import numpy as np
from PIL import Image

from seam.calibrate import score_image
from seam.ela import ela_metrics
from seam.io import jpeg_roundtrip
from seam.noise import noise_metrics
from seam.report import assess
from seam.spectrum import spectrum_metrics

TMP = "/tmp/seam-tests"


def _photo(seed: int = 7, size: int = 256) -> np.ndarray:
    rng = np.random.default_rng(seed)
    base = rng.normal(120, 18, (size, size, 3))
    return base.clip(0, 255).astype(np.uint8)


def _save(arr: np.ndarray, name: str) -> str:
    import os

    os.makedirs(TMP, exist_ok=True)
    path = f"{TMP}/{name}"
    Image.fromarray(arr).save(path)
    return path


class SpectrumTests(unittest.TestCase):
    def test_flat_noise_has_no_peak(self):
        m = spectrum_metrics(_photo())
        self.assertLess(m["spectrum_prominence"], 3.0, "a flat spectrum is not a periodicity")

    def test_an_eight_pixel_grid_is_attributed_to_jpeg(self):
        img = _photo().astype(np.float32)
        x = np.arange(img.shape[1])
        img += 30 * np.cos(2 * np.pi * x / 8)[None, :, None]
        m = spectrum_metrics(img.clip(0, 255).astype(np.uint8))
        self.assertTrue(m["spectrum_near_jpeg"])
        self.assertEqual(assess({**score_image(_save(img.clip(0, 255).astype(np.uint8), "g8.png"))})["verdicts"]["spectrum"], "unexplained")

    def test_a_sixteen_pixel_grid_is_not_written_off_as_jpeg(self):
        img = _photo().astype(np.float32)
        x = np.arange(img.shape[1])
        img += 30 * np.cos(2 * np.pi * x / 16)[None, :, None]
        m = spectrum_metrics(img.clip(0, 255).astype(np.uint8))
        self.assertFalse(m["spectrum_near_jpeg"])
        self.assertGreater(m["spectrum_prominence"], 6.0)


class NoiseTests(unittest.TestCase):
    def test_a_smoothed_core_is_flagged(self):
        img = _photo()
        smooth = img.astype(np.float32)
        patch = smooth[64:192, 64:192]
        padded = np.pad(patch, ((1, 1), (1, 1), (0, 0)), mode="edge")
        blurred = padded[1:-1, 1:-1].copy()
        for _ in range(6):
            blurred = (blurred + np.roll(blurred, 1, 1) + np.roll(blurred, -1, 1)) / 3
        smooth[64:192, 64:192] = blurred
        m = noise_metrics(smooth.clip(0, 255).astype(np.uint8))
        self.assertLess(m["noise_ratio"], 0.9, "a smooth core should lose residual energy")

    def test_an_untouched_frame_sits_near_one(self):
        self.assertAlmostEqual(noise_metrics(_photo())["noise_ratio"], 1.0, delta=0.12)


class ElaTests(unittest.TestCase):
    def test_a_pasted_recompressed_patch_reads_cold(self):
        img = _photo()
        patch = jpeg_roundtrip(img[0:128, 0:128], quality=55)
        img = img.copy()
        img[0:128, 0:128] = patch
        m = ela_metrics(img)
        self.assertGreaterEqual(m["ela_cold_share"], 0.15, "already-quantised pixels error less")
        self.assertIn("suspect", assess({**m, "spectrum_period": 16.0, "spectrum_prominence": 1.0,
                                         "spectrum_near_jpeg": False, "noise_ratio": 1.0})["verdicts"]["ela"])

    def test_a_pasted_raw_patch_reads_hot(self):
        img = jpeg_roundtrip(_photo(), quality=60)
        img = img.copy()
        rng = np.random.default_rng(11)
        img[0:128, 0:128] = rng.normal(120, 18, (128, 128, 3)).clip(0, 255).astype(np.uint8)
        m = ela_metrics(img)
        self.assertGreaterEqual(m["ela_hot_share"], 0.02, "raw pixels error more than quantised ones")

    def test_a_single_generation_frame_does_not(self):
        m = ela_metrics(jpeg_roundtrip(_photo(), quality=90))
        self.assertLess(m["ela_ratio"], 3.0)


class ReportTests(unittest.TestCase):
    def test_two_tells_say_second_look_and_one_does_not(self):
        one = {"ela_ratio": 1.0, "ela_hot_share": 0.0, "spectrum_period": 16.0,
               "spectrum_prominence": 12.0, "spectrum_near_jpeg": False, "noise_ratio": 1.0}
        two = dict(one, ela_ratio=5.0, ela_hot_share=0.1)
        self.assertEqual(assess(one)["hits"], 1)
        self.assertEqual(assess(two)["hits"], 2)
        self.assertIn("second look", assess(two)["headline"])
        self.assertIn("not evidence", assess(one)["headline"])

    def test_the_report_never_calls_a_clean_result_authentic(self):
        quiet = {"ela_ratio": 1.0, "ela_hot_share": 0.0, "spectrum_period": 16.0,
                 "spectrum_prominence": 1.0, "spectrum_near_jpeg": False, "noise_ratio": 1.0}
        self.assertIn("not the same as authentic", assess(quiet)["headline"])


if __name__ == "__main__":
    unittest.main()
