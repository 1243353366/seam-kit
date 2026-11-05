"""The adjudicator's job is to refuse conclusions the evidence cannot carry."""
from __future__ import annotations

import unittest

from lab import adjudicate as adj


def signals(**verdicts):
    return {name: {"verdict": v} for name, v in verdicts.items()}


class GradeLadderTests(unittest.TestCase):
    def test_one_agreeing_signal_is_suspected(self):
        claim = adj.media_claim(signals(noise_ratio="suspect", chroma_step="clean"))
        self.assertEqual(claim["grade"], "suspected")

    def test_two_agreeing_signals_are_corroborated(self):
        claim = adj.media_claim(signals(noise_ratio="suspect", seam_edge="suspect"))
        self.assertEqual(claim["grade"], "corroborated")

    def test_no_signal_is_unknown_not_innocent(self):
        claim = adj.media_claim(signals(noise_ratio="clean", seam_edge="clean"))
        self.assertEqual(claim["grade"], "unknown")
        self.assertIn("no provenance", " ".join(claim["limitations"]))

    def test_provenance_is_what_confirms(self):
        claim = adj.media_claim(
            signals(noise_ratio="suspect"), provenance={"chain_intact": True, "insertion_evidence": True}
        )
        self.assertEqual(claim["grade"], "confirmed")

    def test_a_broken_chain_is_a_stated_limitation_not_a_silent_pass(self):
        claim = adj.media_claim(
            signals(noise_ratio="suspect"),
            provenance={"chain_intact": False, "insertion_evidence": True},
        )
        self.assertEqual(claim["grade"], "suspected")
        self.assertIn("custody chain broken", " ".join(claim["limitations"]))

    def test_disagreement_is_recorded_as_a_limitation(self):
        claim = adj.media_claim(signals(noise_ratio="suspect", seam_edge="clean"))
        self.assertIn("signals disagree", " ".join(claim["limitations"]))


class EventClaimTests(unittest.TestCase):
    """The ceiling: media cannot prove an event did not happen."""

    def test_confirmed_media_alone_still_cannot_claim_the_event_was_false(self):
        media = adj.media_claim(
            signals(noise_ratio="suspect", seam_edge="suspect"),
            provenance={"chain_intact": True, "insertion_evidence": True},
        )
        self.assertEqual(media["grade"], "confirmed")
        claim = adj.event_claim(media)
        self.assertEqual(claim["grade"], "unknown")
        self.assertIn("media alone", claim["reason"])

    def test_an_independent_source_lifts_it_one_rung(self):
        media = adj.media_claim(signals(noise_ratio="suspect", seam_edge="suspect"))
        claim = adj.event_claim(media, [{"independent": True, "source": "venue log"}])
        self.assertEqual(claim["grade"], "corroborated")

    def test_a_source_that_is_not_independent_does_not_count(self):
        media = adj.media_claim(signals(noise_ratio="suspect", seam_edge="suspect"))
        claim = adj.event_claim(media, [{"independent": False, "source": "the same camera"}])
        self.assertEqual(claim["grade"], "unknown")


class CalibrationTests(unittest.TestCase):
    def test_a_coin_scores_a_quarter(self):
        self.assertAlmostEqual(adj.brier([1.0, 0.0], [1, 0], w=0.0, b=0.0), 0.25)

    def test_auc_is_one_when_the_order_is_right(self):
        self.assertEqual(adj.auc([0.9, 0.8, 0.2, 0.1], [1, 1, 0, 0]), 1.0)

    def test_auc_falls_below_half_when_the_signal_points_backwards(self):
        self.assertEqual(adj.auc([0.1, 0.2, 0.8, 0.9], [1, 1, 0, 0]), 0.0)

    def test_threshold_honours_the_target_rate(self):
        negatives = [0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.05]
        threshold = adj.threshold_for_fpr(negatives, 0.2)
        flagged = sum(1 for s in negatives if s >= threshold)
        self.assertLessEqual(flagged, 2)


class HoldoutTests(unittest.TestCase):
    def test_the_holdout_is_scored_separately_from_the_families_it_learned(self):
        result = adj.evaluate(holdout="hard", count=4)
        self.assertEqual(result["holdout"], "hard")
        self.assertEqual(set(result["families"]), set(adj.FAMILIES))
        for name, stats in result["families"].items():
            self.assertGreaterEqual(stats["auc"], 0.0, name)
            self.assertLessEqual(stats["auc"], 1.0, name)
            self.assertGreater(stats["n"], 0, name)

    def test_the_report_says_which_family_it_never_saw(self):
        result = adj.evaluate(holdout="light", count=4)
        self.assertEqual(result["holdout"], "light")
        self.assertTrue(result["reliability_holdout"])


if __name__ == "__main__":
    unittest.main()
