"""The grading rules, one test each.

The difference between confirmed and suspected is the whole point of this module, so every
rule that can downgrade a claim gets a test that would fail if the downgrade disappeared.
"""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from lab.graph import Observation, Site, correlate, load_case

PAR = Site("PAR", 48.8606, 2.3376)
LYS = Site("LYS", 45.7640, 4.8357)
SITES = {"PAR": PAR, "LYS": LYS}


def obs(event, site, minute, **kw):
    """Minute offsets run past 59 on purpose: two hours later is 122, not 16:02."""
    base = datetime(2026, 11, 5, 14, 0, tzinfo=timezone.utc) + timedelta(minutes=minute)
    kw.setdefault("drift_uncertainty_s", 2.0)
    return Observation(event_id=event, site_id=site, subject="assane", at=base, **kw)


class ContradictionTests(unittest.TestCase):
    def test_two_sites_three_minutes_apart_is_confirmed(self):
        claim = correlate([obs("a1", "PAR", 2), obs("a2", "LYS", 5)], SITES)["claims"][0]
        self.assertEqual(claim["grade"], "confirmed")
        self.assertIn("cannot have been", claim["claim"])

    def test_same_gap_is_only_a_suspicion_when_identity_was_never_verified(self):
        claim = correlate(
            [obs("a1", "PAR", 2), obs("a2", "LYS", 5, identity_verified=False)], SITES
        )["claims"][0]
        self.assertEqual(claim["grade"], "suspected")
        self.assertIn("identity verified at both sites", claim["missing"])

    def test_a_broken_custody_chain_downgrades_it(self):
        claim = correlate([obs("a1", "PAR", 2, custody_ok=False), obs("a2", "LYS", 5)], SITES)["claims"][0]
        self.assertEqual(claim["grade"], "suspected")
        self.assertIn("intact custody chain for both exhibits", claim["missing"])

    def test_an_undeclared_clock_is_not_treated_as_a_perfect_clock(self):
        claim = correlate(
            [obs("a1", "PAR", 2, drift_uncertainty_s=None, drift_s=0), obs("a2", "LYS", 5)], SITES
        )["claims"][0]
        self.assertEqual(claim["grade"], "suspected")
        self.assertIn("declared clock uncertainty for both cameras", claim["missing"])

    def test_wide_clock_uncertainty_stops_it_being_confirmed(self):
        # 392 km in 3 minutes needs 7678 km/h. Give each camera 96 minutes of uncertainty and the
        # generous gap is 195 minutes: 120 km/h, entirely possible. A documented clock can rescue
        # an apparent contradiction, which is exactly why the confirmed grade requires the gap to
        # survive that generosity.
        claim = correlate(
            [obs("a1", "PAR", 2, drift_uncertainty_s=5800), obs("a2", "LYS", 5, drift_uncertainty_s=5800)],
            SITES,
        )["claims"][0]
        self.assertNotEqual(claim["grade"], "confirmed")


class ConsistencyTests(unittest.TestCase):
    def test_two_hours_apart_is_one_person_travelling(self):
        claim = correlate([obs("a1", "PAR", 2), obs("a2", "LYS", 122)], SITES)["claims"][0]
        self.assertEqual(claim["grade"], "corroborated")
        self.assertIn("consistent", claim["claim"])

    def test_a_marginal_speed_is_suspicious_not_confirmed(self):
        # 392 km in 65 minutes is 362 km/h: over the limit, under the dismissal threshold.
        claim = correlate([obs("a1", "PAR", 2), obs("a2", "LYS", 67)], SITES)["claims"][0]
        self.assertEqual(claim["grade"], "suspected")
        self.assertIn("implausibly fast", claim["claim"])

    def test_an_unknown_site_is_unknown_rather_than_guessed(self):
        claim = correlate([obs("a1", "PAR", 2), obs("a2", "XXX", 5)], SITES)["claims"][0]
        self.assertEqual(claim["grade"], "unknown")

    def test_load_case_reads_what_the_fixture_files_contain(self):
        payload = {
            "sites": [{"id": "PAR", "lat": 48.86, "lon": 2.33}],
            "events": [{"site": "PAR", "subject": "x", "at": "2026-11-05T14:02:00Z"}],
        }
        observations, sites = load_case(payload)
        self.assertEqual(len(observations), 1)
        self.assertIn("PAR", sites)
        self.assertTrue(observations[0].identity_verified)


if __name__ == "__main__":
    unittest.main()
