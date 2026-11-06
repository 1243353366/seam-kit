"""The case study is the only place the modules have to agree with each other."""
from __future__ import annotations

import os
import shutil
import unittest

os.environ.setdefault("SEAM_KEY", "museum-drill-key-000000000000")

from scenario import museum  # noqa: E402


@unittest.skipIf(shutil.which("ffmpeg") is None, "ffmpeg not installed")
class MuseumCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = museum.investigate()
        cls.claims = {c["id"]: c for c in cls.report["claims"]}

    def test_the_case_is_declared_synthetic(self):
        self.assertTrue(self.report["synthetic"])
        self.assertIn("not about footage from the world", " ".join(self.report["limits"]))

    def test_a_removed_row_is_confirmed_by_the_seal(self):
        self.assertEqual(self.claims["record"]["grade"], "confirmed")
        self.assertGreaterEqual(self.report["evidence"]["rows_lost"], 1)

    def test_media_stays_at_suspected_without_measured_thresholds(self):
        """Two signals agree and the grade still does not move: uncalibrated defaults are not
        operating points, and the case has no measured ones to supply."""
        self.assertEqual(self.claims["media"]["grade"], "suspected")
        self.assertIn("capped by missing calibration", " ".join(self.claims["media"]["limitations"]))

    def test_an_independent_record_is_what_lifts_the_event_claim(self):
        self.assertEqual(self.claims["event"]["grade"], "corroborated")
        self.assertEqual(self.report["evidence"]["event_without_corroboration"], "unknown")

    def test_concealment_needs_more_than_one_shape(self):
        self.assertGreaterEqual(len(self.report["evidence"]["concealment"]), 2)
        self.assertEqual(self.claims["concealment"]["grade"], "corroborated")

    def test_a_recognised_operator_is_still_refused(self):
        access = self.claims["access"]
        self.assertTrue(access["authenticated"])
        self.assertFalse(access["authorized"])
        self.assertEqual(access["grade"], "unknown")

    def test_the_report_carries_its_limits(self):
        for claim in self.report["claims"]:
            self.assertTrue(claim["limitations"], claim["id"])
        markdown = museum.to_markdown(self.report)
        self.assertIn("What the evidence cannot carry", markdown)
        self.assertIn("What this run cannot establish", markdown)
