"""Attack the association model itself, not the accidental failures that led to it."""
from __future__ import annotations

import unittest

from lab import simulate_incident as sim
from lab import threatlens as lens


def burst(host="fs-01", machine=None, count=90, start=100.0) -> list[dict]:
    out = []
    for i in range(count):
        e = {"kind": "file", "at": start + i * 0.1, "host": host,
             "path": f"D:/x/d{i}.locked", "op": "write"}
        if machine:
            e["machine_id"] = machine
        out.append(e)
    return out


class HostIdentityCollision(unittest.TestCase):
    def test_two_machines_sharing_a_hostname_are_not_one_incident(self):
        """Imaging and cloning produce exactly this: one name, two machines."""
        events = burst(machine="GUID-A") + [
            {"kind": "config", "at": 101.0, "host": "fs-01", "machine_id": "GUID-B",
             "key": "SystemRestore", "op": "disable"}]
        claim = lens.analyse_ransomware(events)
        self.assertEqual(claim["grade"], "suspected", "a config from another machine was borrowed")
        self.assertIn("host identity collision", " ".join(claim["limitations"]))

    def test_without_a_machine_identity_the_report_admits_it_cannot_tell(self):
        events = burst() + [{"kind": "config", "at": 101.0, "host": "fs-01",
                             "key": "SystemRestore", "op": "disable"}]
        claim = lens.analyse_ransomware(events)
        self.assertEqual(claim["grade"], "corroborated")
        self.assertIn("machine identity", " ".join(claim["limitations"]))


class ClockSkew(unittest.TestCase):
    def test_proximity_is_reported_as_observed_when_no_clocks_are_verified(self):
        report = lens.investigate(sim.ransomware_burst(), egress_baseline=10_000_000)
        self.assertEqual(report["claims"]["temporal_reliability"]["basis"], "observed")

    def test_verified_clock_evidence_changes_the_basis_and_the_wording(self):
        events = sim.ransomware_burst() + [
            {"kind": "clock", "at": 400.0, "host": "fs-01", "offset_s": 0.4, "verified": True}]
        report = lens.investigate(events, egress_baseline=10_000_000)
        basis = report["claims"]["temporal_reliability"]
        self.assertEqual(basis["basis"], "verified")
        self.assertEqual(basis["max_absolute_offset_s"], 0.4)

    def test_a_clock_claim_about_one_host_does_not_cover_the_others(self):
        events = sim.ransomware_burst() + [
            {"kind": "clock", "at": 400.0, "host": "fs-01", "offset_s": 0.1, "verified": True},
            {"kind": "file", "at": 401.0, "host": "ws-02", "path": "a", "op": "write"}]
        basis = lens.investigate(events, egress_baseline=10_000_000)["claims"]["temporal_reliability"]
        self.assertEqual(basis["basis"], "observed")
        self.assertIn("ws-02", basis["unverified_hosts"])

    def test_skew_beyond_the_window_breaks_association_not_reality(self):
        """Two events thirty-one minutes apart on a badly skewed clock look unassociated. That is a
        limit of the evidence, and the report must not upgrade it to a fact."""
        events = burst(start=100.0) + [
            {"kind": "config", "at": 100.0 + 3600 + 60, "host": "fs-01",
             "key": "SystemRestore", "op": "disable"}]
        claim = lens.analyse_ransomware(events)
        self.assertEqual(claim["grade"], "suspected")
        self.assertIn("not associated", " ".join(claim["limitations"]))


class HostMigration(unittest.TestCase):
    def test_a_rename_keeps_one_incident(self):
        events = burst(machine="GUID-C", start=100.0)
        events.append({"kind": "config", "at": 110.0, "host": "fs-01-renamed", "machine_id": "GUID-C",
                       "key": "SystemRestore", "op": "disable"})
        claim = lens.analyse_ransomware(events)
        self.assertEqual(claim["grade"], "corroborated")
        self.assertIn("appears as", " ".join(claim["limitations"]))
        self.assertIn("fs-01-renamed", " ".join(claim["limitations"]))

    def test_without_identity_a_rename_splits_the_incident(self):
        events = burst(start=100.0) + [
            {"kind": "config", "at": 110.0, "host": "fs-01-renamed", "key": "SystemRestore", "op": "disable"}]
        self.assertEqual(lens.analyse_ransomware(events)["grade"], "suspected")


class AssociationTransitivity(unittest.TestCase):
    def test_two_hops_do_not_make_one_incident(self):
        """A supports B, B supports C, but A and C are two hours apart. C must not join."""
        events = burst(start=100.0) + [
            {"kind": "config", "at": 100.0 + 1800, "host": "fs-01", "key": "SystemRestore", "op": "disable"},
            {"kind": "network", "at": 100.0 + 5400, "host": "fs-01", "dst": "drop.example",
             "proto": "https", "bytes": 900_000_000}]
        claim = lens.analyse_ransomware(events, egress_baseline=10_000_000)
        self.assertEqual(claim["sources"], ["config", "file"])
        self.assertNotIn("egress", " ".join(claim["observed"]))
        self.assertIn("not transitive", " ".join(claim["limitations"]))

    def test_the_anchor_rule_is_reported(self):
        report = lens.investigate(sim.ransomware_burst(), egress_baseline=10_000_000)
        rule = report["claims"]["incident_association"]["anchor_rule"]
        self.assertIn("never chained", rule)


class ThreeClaimsStaySeparate(unittest.TestCase):
    def test_each_claim_is_reported_on_its_own(self):
        report = lens.investigate(sim.ransomware_burst(), egress_baseline=10_000_000)
        claims = report["claims"]
        self.assertEqual(set(claims), {"source_independence", "incident_association",
                                       "temporal_reliability"})
        self.assertEqual(claims["temporal_reliability"]["basis"], "observed",
                         "verified association must not imply verified clocks")
        self.assertIn("says nothing about clocks", claims["source_independence"]["note"])
        self.assertIn("says nothing about clock reliability", claims["incident_association"]["note"])
