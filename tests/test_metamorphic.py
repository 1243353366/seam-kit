"""The matrix as tests, so a regression in association or ordering fails CI rather than a review."""
from __future__ import annotations

import unittest

from lab import simulate_incident as sim
from lab import threatlens as lens
from tools import metamorphic as meta


class MetamorphicMatrix(unittest.TestCase):
    def test_every_transformation_behaves_as_declared(self):
        for row in meta.run():
            self.assertTrue(row["passed"], f"{row['case']}: expected {row['expects']}, got {row['grade']}")

    def test_case_and_whitespace_do_not_change_the_grade(self):
        base = lens.investigate(meta.base_incident(), egress_baseline=meta.EGRESS_BASELINE)
        loud = lens.investigate(meta.recase(meta.base_incident()), egress_baseline=meta.EGRESS_BASELINE)
        self.assertEqual(base["grade"], loud["grade"])

    def test_a_burst_is_found_when_it_straddles_a_minute_boundary(self):
        report = lens.investigate(meta.straddle([]))
        claim = next(f for f in report["findings"] if f["behaviour"] == "ransomware_impact")
        self.assertIn("within 60s", " ".join(claim["observed"]))

    def test_evidence_moved_to_another_host_loses_corroboration(self):
        base = lens.investigate(meta.base_incident(), egress_baseline=meta.EGRESS_BASELINE)
        split = lens.investigate(meta.separate_hosts(meta.base_incident()), egress_baseline=meta.EGRESS_BASELINE)
        self.assertEqual(base["grade"], "corroborated")
        self.assertEqual(split["grade"], "suspected")
        self.assertIn("not associated", " ".join(split["limitations"]))

    def test_evidence_moved_days_later_loses_corroboration(self):
        split = lens.investigate(meta.separate_time(meta.base_incident()), egress_baseline=meta.EGRESS_BASELINE)
        self.assertEqual(split["grade"], "suspected")

    def test_unrelated_traffic_does_not_lift_the_grade(self):
        base = lens.investigate(meta.base_incident(), egress_baseline=meta.EGRESS_BASELINE)
        noisy = lens.investigate(meta.contaminate(meta.base_incident()), egress_baseline=meta.EGRESS_BASELINE)
        self.assertEqual(base["grade"], noisy["grade"])

    def test_ordering_does_not_change_the_story_told(self):
        first = lens.investigate(meta.base_incident(), egress_baseline=meta.EGRESS_BASELINE)
        for seed in range(8):
            again = lens.investigate(meta.shuffle(meta.base_incident(), seed), egress_baseline=meta.EGRESS_BASELINE)
            self.assertEqual([f["observed"] for f in first["findings"]],
                             [f["observed"] for f in again["findings"]], f"seed {seed}")

    def test_hostile_numbers_are_refused_without_raising(self):
        report = lens.investigate(meta.hostile_numbers(meta.base_incident()), egress_baseline=meta.EGRESS_BASELINE)
        self.assertGreaterEqual(report["events_rejected"], 3)
        self.assertTrue(report["schema_problems"])

    def test_a_recovery_config_on_another_host_is_not_ransomware_corroboration(self):
        events = [{"kind": "file", "at": 10.0 + i * 0.1, "host": "fs-02",
                   "path": f"D:/x/d{i}.locked", "op": "write"} for i in range(90)]
        events.append({"kind": "config", "at": 11.0, "host": "ws-77", "key": "SystemRestore", "op": "disable"})
        claim = lens.analyse_ransomware(events)
        self.assertEqual(claim["grade"], "suspected")
        self.assertIn("not associated", " ".join(claim["limitations"]))

    def test_an_autostart_write_on_another_host_is_not_trojan_corroboration(self):
        """One source on ws-03 plus a second source on ws-88 is still one source."""
        events = [{"kind": "process", "at": 300.0, "host": "ws-03", "pid": 2200, "ppid": 1,
                   "image": "winword.exe", "parent": "explorer.exe", "signed": True},
                  {"kind": "process", "at": 301.0, "host": "ws-03", "pid": 2210, "ppid": 2200,
                   "image": "powershell.exe", "parent": "winword.exe", "signed": True},
                  {"kind": "file", "at": 305.0, "host": "ws-88",
                   "path": "C:/Users/b/Start Menu/Programs/Startup/x.lnk", "op": "write"}]
        claim = lens.analyse_trojan(events)
        self.assertEqual(claim["grade"], "suspected")
        self.assertEqual(claim["sources"], ["process"])
        self.assertIn("not associated", " ".join(claim["limitations"]))
