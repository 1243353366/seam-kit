"""Behaviour, never names. Every test here asks the same question from a different angle."""
from __future__ import annotations

import inspect
import unittest

from lab import simulate_incident as sim
from lab import threatlens as lens


class BenignControl(unittest.TestCase):
    def test_an_ordinary_day_produces_nothing(self):
        report = lens.investigate(sim.benign_day())
        self.assertEqual(report["grade"], "unknown")
        for finding in report["findings"]:
            self.assertEqual(finding["grade"], "unknown", finding["behaviour"])


class Propagation(unittest.TestCase):
    def test_fanout_and_service_creation_corroborate_each_other(self):
        report = lens.investigate(sim.worm_spread())
        worm = next(f for f in report["findings"] if f["behaviour"] == "worm_propagation")
        self.assertEqual(worm["grade"], "corroborated")
        self.assertEqual(worm["sources"], ["network", "service"])
        self.assertIn("T1021 remote services", worm["techniques"])

    def test_fanout_alone_is_not_corroboration(self):
        """Two facts read off the same log are one source, and one source is one rung."""
        events = [e for e in sim.worm_spread() if e["kind"] == "network"]
        worm = lens.analyse_worm(events)
        self.assertEqual(worm["grade"], "suspected")
        self.assertEqual(worm["independent_channels"], 1)


class Execution(unittest.TestCase):
    def test_ancestry_persistence_and_egress_corroborate(self):
        report = lens.investigate(
            sim.trojan_persistence(), known_destinations={"updates.vendor.example"}
        )
        trojan = next(f for f in report["findings"] if f["behaviour"] == "trojan_execution")
        self.assertEqual(trojan["grade"], "corroborated")
        self.assertIn("process", trojan["sources"])
        self.assertIn("file", trojan["sources"])

    def test_a_valid_signature_is_not_reassurance(self):
        report = lens.investigate(
            sim.trojan_persistence(), known_destinations={"updates.vendor.example"}
        )
        trojan = next(f for f in report["findings"] if f["behaviour"] == "trojan_execution")
        self.assertIn("proves who built the file, not what it does", " ".join(trojan["limitations"]))


class Impact(unittest.TestCase):
    def test_a_burst_with_egress_is_corroborated(self):
        report = lens.investigate(sim.ransomware_burst(), egress_baseline=10_000_000)
        claim = next(f for f in report["findings"] if f["behaviour"] == "ransomware_impact")
        self.assertEqual(claim["grade"], "corroborated")
        self.assertIn("T1486 data encrypted for impact", claim["techniques"])

    def test_a_burst_without_a_second_source_stays_suspected(self):
        events = [e for e in sim.ransomware_burst() if e["kind"] == "file"]
        claim = lens.analyse_ransomware(events)
        self.assertEqual(claim["grade"], "suspected")
        self.assertIn("one source", " ".join(claim["observed"]))


class SignatureFree(unittest.TestCase):
    def test_a_file_named_like_malware_proves_nothing(self):
        events = [{"kind": "process", "at": 1.0, "host": "h", "image": "ransomware.exe",
                   "parent": "explorer.exe", "signed": False}]
        self.assertEqual(lens.investigate(events)["grade"], "unknown")

    def test_the_api_takes_no_names_hashes_or_signatures(self):
        params = set(inspect.signature(lens.investigate).parameters)
        self.assertFalse(params & {"name", "hash", "signature", "malware", "family"})
        report = lens.investigate(sim.worm_spread())
        self.assertTrue(report["signature_free"])
        self.assertIn("file hashes", report["inputs_not_used"])

    def test_nothing_is_ever_confirmed(self):
        for events in (sim.benign_day(), sim.worm_spread(), sim.trojan_persistence(),
                       sim.ransomware_burst()):
            report = lens.investigate(events, egress_baseline=10_000_000)
            self.assertNotEqual(report["grade"], "confirmed")
            self.assertFalse(report["confirmed"])


class Correlation(unittest.TestCase):
    def test_two_behaviours_make_one_incident_with_its_limits_attached(self):
        events = sim.worm_spread() + sim.ransomware_burst()
        report = lens.investigate(events, egress_baseline=10_000_000)
        self.assertEqual(report["grade"], "corroborated")
        self.assertGreaterEqual(len(report["channels"]), 2)
        self.assertTrue(any("no shared clock discipline" in l for l in report["limitations"]))
        self.assertTrue(report["techniques"])

    def test_software_drift_is_its_own_channel(self):
        baseline = {"binary_digest": "a" * 64, "version": "4.2.0",
                    "destinations": ["updates.vendor.example"], "telemetry_bytes": 1000}
        observed = {"binary_digest": "b" * 64, "version": "4.2.0",
                    "destinations": ["updates.vendor.example", "cdn-relay-9.example"],
                    "telemetry_bytes": 9000}
        finding = lens.analyse_software_integrity(baseline, observed)
        self.assertEqual(finding["grade"], "corroborated")
        self.assertEqual(finding["sources"], ["binary", "network"])
        self.assertIn("updates change digests by design", " ".join(finding["limitations"]))
