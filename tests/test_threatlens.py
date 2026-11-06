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
        self.assertIn("count once", " ".join(claim["observed"]))


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


class TelemetrySchema(unittest.TestCase):
    """One schema, or every engine invents its own reading of an event."""

    def test_a_stream_with_no_host_is_refused(self):
        from lab import telemetry
        with self.assertRaises(telemetry.SchemaError):
            telemetry.check([{"kind": "file", "at": 1.0, "path": "a", "op": "write"}])

    def test_an_invented_file_operation_is_refused(self):
        from lab import telemetry
        found = telemetry.problems([{"kind": "file", "at": 1.0, "host": "h", "path": "a", "op": "exfiltrate"}])
        self.assertTrue(any("not one of" in f for f in found))

    def test_problems_are_reported_not_swallowed(self):
        report = lens.investigate([{"kind": "nonsense", "at": 1.0, "host": "h"}])
        self.assertTrue(report["schema_problems"])

    def test_hosts_and_images_are_normalised(self):
        from lab import telemetry
        out = telemetry.normalise({"kind": "PROCESS", "at": "12", "host": " WS-01 ", "image": "Cmd.exe"})
        self.assertEqual(out["host"], "ws-01")
        self.assertEqual(out["at"], 12.0)

    def test_a_locked_extension_is_not_the_original(self):
        from lab import telemetry
        self.assertEqual(telemetry.extension("D:/shares/a.xlsx.locked"), ".locked")


class RenameAndRecovery(unittest.TestCase):
    def test_a_rename_burst_is_seen_even_without_new_writes(self):
        renames = [{"kind": "file", "at": 10.0 + i, "host": "fs-02",
                    "path": f"D:/x/doc{i}.locked", "op": "rename"} for i in range(60)]
        claim = lens.analyse_ransomware(renames)
        self.assertIn("rename events", " ".join(claim["observed"]))
        self.assertEqual(claim["grade"], "suspected")

    def test_weakened_recovery_configuration_is_its_own_source(self):
        events = [{"kind": "file", "at": 1.0, "host": "fs-02", "path": f"D:/x/doc{i}.locked",
                   "op": "write"} for i in range(90)]
        events.append({"kind": "config", "at": 2.0, "host": "fs-02",
                       "key": "SystemRestore", "op": "disable"})
        claim = lens.analyse_ransomware(events)
        self.assertEqual(claim["grade"], "corroborated")
        self.assertEqual(claim["sources"], ["config", "file"])


class PublisherAndDependencies(unittest.TestCase):
    def test_a_publisher_change_counts_as_a_binary_observation(self):
        baseline = {"binary_digest": "a" * 64, "publisher": "Acme Ltd"}
        observed = {"binary_digest": "a" * 64, "publisher": "Acme Holdings"}
        claim = lens.analyse_software_integrity(baseline, observed)
        self.assertEqual(claim["grade"], "suspected")
        self.assertIn("publisher changed", claim["observed"][0])

    def test_a_new_bundled_dependency_is_its_own_source(self):
        baseline = {"binary_digest": "a" * 64, "dependencies": ["libssl"]}
        observed = {"binary_digest": "b" * 64, "dependencies": ["libssl", "libcrypto-extra"]}
        claim = lens.analyse_software_integrity(baseline, observed)
        self.assertEqual(claim["sources"], ["binary", "dependency"])


class PrivilegeAndSimilarity(unittest.TestCase):
    def test_elevation_alone_proves_nothing(self):
        events = [{"kind": "privilege", "at": 1.0, "host": "ws-03", "user": "a", "elevated": True}]
        claim = lens.analyse_trojan(events)
        self.assertEqual(claim["grade"], "unknown")

    def test_elevation_beside_ancestry_and_persistence_is_a_third_source(self):
        events = sim.trojan_persistence() + [
            {"kind": "privilege", "at": 304.0, "host": "ws-03", "user": "a", "elevated": True}]
        claim = lens.analyse_trojan(events, known_destinations={"updates.vendor.example"})
        self.assertIn("privilege", claim["sources"])

    def test_identical_process_shapes_are_only_an_edge_when_the_hosts_talk(self):
        """A standardised build puts the same image everywhere. That is not evidence."""
        quiet = sim.worm_spread()
        self.assertFalse(lens.pattern_similarity(quiet),
                         "identical shapes with no coupling between the hosts is a build, not a spread")
        spread = quiet + [
            {"kind": "network", "at": 210.0, "host": f"fs-{i:02d}", "dst": f"fs-{i + 1:02d}",
             "proto": "smb", "bytes": 100} for i in range(4)]
        self.assertTrue(lens.pattern_similarity(spread))


class EvidenceRecord(unittest.TestCase):
    def setUp(self):
        self.report = lens.investigate(sim.ransomware_burst(), egress_baseline=10_000_000)
        self.record = lens.evidence_record("CASE-001", "lab-win-02", self.report)

    def test_every_finding_carries_its_benign_twins(self):
        for finding in self.record["findings"]:
            self.assertTrue(finding["alternative_explanations"], finding["behaviour"])

    def test_the_conclusion_does_not_claim_a_detection(self):
        text = lens.as_text(self.record).lower()
        self.assertNotIn("detected", text)
        self.assertIn("examiner review", text)
        self.assertFalse(self.record["confirmed"])

    def test_the_record_is_storable_beside_a_media_finding(self):
        for key in ("case", "host", "grade", "corroboration", "limitations", "next_step"):
            self.assertIn(key, self.record)
