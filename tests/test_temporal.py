"""Sequences with a known difference, scored through the same three measurements."""
from __future__ import annotations

import shutil
import tempfile
import unittest

import numpy as np

from lab import synth, temporal


def authentic(count: int = 10) -> np.ndarray:
    """Same face, sensor noise only. Nothing changes between frames but the grain."""
    return np.stack([synth.face_frame(seed=i, size=192) for i in range(count)])


def drifting(count: int = 10) -> np.ndarray:
    """The face walks sideways frame by frame: the geometry stops agreeing with itself."""
    base = synth.face_frame(seed=500, size=192)
    return np.stack([np.roll(base, shift=i * 3, axis=1) for i in range(count)])


def shimmering(count: int = 10) -> np.ndarray:
    """Exposure pulses every other frame."""
    frames = authentic(count).copy()
    for i in range(1, len(frames), 2):
        frames[i] = np.clip(frames[i].astype(np.int16) + 18, 0, 255).astype(np.uint8)
    return frames


def cut_sequence(count: int = 10) -> np.ndarray:
    """Two different scenes spliced together, which is a cut rather than a gesture."""
    first = authentic(count // 2)
    other = np.stack([synth.face_frame(seed=900 + i, size=192) for i in range(count - count // 2)])
    other = np.clip(other.astype(np.int16) + 60, 0, 255).astype(np.uint8)
    return np.concatenate([first, other])


class SignalTests(unittest.TestCase):
    def test_a_still_sequence_is_quiet_on_all_three(self):
        m = temporal.analyse(authentic())
        self.assertLess(m["drift"], 0.05)
        self.assertLess(m["flicker"], 0.06)

    def test_identity_drift_shows_up_in_drift(self):
        m = temporal.analyse(drifting())
        self.assertGreater(m["drift"], 0.20, "a face that will not hold still is the point")

    def test_exposure_pulse_shows_up_in_flicker(self):
        m = temporal.analyse(shimmering())
        self.assertGreater(m["flicker"], 0.10)

    def test_a_splice_shows_up_as_a_cut(self):
        m = temporal.analyse(cut_sequence())
        self.assertGreater(m["cut"], 6.0)

    def test_short_sequences_do_not_raise(self):
        one = authentic(1)
        self.assertEqual(temporal.analyse(one)["frames"], 1)


class ContainerTests(unittest.TestCase):
    """The file path matters: a codec can hide or invent grain, so it is tested, not assumed."""

    def setUp(self):
        if shutil.which("ffmpeg") is None:
            self.skipTest("ffmpeg not installed")

    def test_a_sequence_survives_h264_and_still_scores(self):
        frames = drifting()
        with tempfile.TemporaryDirectory() as tmp:
            path = f"{tmp}/clip.mp4"
            temporal.write_video(frames, path)
            decoded = temporal.load_video(path, size=192)
        self.assertGreater(len(decoded), 4)
        m = temporal.analyse(decoded)
        self.assertGreater(m["drift"], 0.10, "compression should soften the signal, not erase it")
        self.assertEqual(m["frames"], len(decoded))
