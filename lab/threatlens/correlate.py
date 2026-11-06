"""Several engines, one incident, and a record shaped for an examiner rather than a dashboard."""
from __future__ import annotations

from ._common import SIGNATURE_FREE_INPUTS, grade_for
from lab.telemetry import problems

#: What else could produce each shape. Attached to every finding, because a detector that cannot
#: name a benign twin has not finished thinking.
ALTERNATIVES = {
    "worm_propagation": ["a deployment or patch-management tool", "a vulnerability scanner sweeping the estate",
                         "a backup or sync agent"],
    "trojan_execution": ["an installer that legitimately spawns a script",
                         "a macro-enabled document doing approved work",
                         "a vendor update writing an autostart entry"],
    "software_drift": ["a routine application update", "a repackaged install by IT",
                       "a downgrade during a rollback"],
    "ransomware_impact": ["a bulk backup operation", "a software update rewriting its files",
                          "a legitimate mass file conversion"],
}


def correlate(findings: list[dict]) -> dict:
    live = [f for f in findings if f["grade"] != "unknown"]
    channels = {f["behaviour"] for f in live}
    grades = [f["grade"] for f in live]
    if any(g == "corroborated" for g in grades) or len(channels) >= 2:
        grade = "corroborated"
    elif grades:
        grade = "suspected"
    else:
        grade = "unknown"
    limits = [l for f in live for l in f["limitations"]]
    limits.append("correlation here is by host and time only: no shared clock discipline is enforced")
    return {
        "grade": grade,
        "channels": sorted(channels),
        "independent_observations": sum(f["independent_channels"] for f in live),
        "techniques": sorted({t for f in live for t in f["techniques"]}),
        "affected_hosts": sorted({h for f in live for h in f.get("hosts", [])}),
        "observed": [o for f in live for o in f["observed"]],
        "alternatives": {f["behaviour"]: ALTERNATIVES.get(f["behaviour"], []) for f in live},
        "limitations": limits,
        "findings": findings,
    }
