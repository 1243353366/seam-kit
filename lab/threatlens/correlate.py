"""Several engines, one incident, and a record shaped for an examiner rather than a dashboard."""
from __future__ import annotations

from ._common import ASSOCIATION_WINDOW_S, SIGNATURE_FREE_INPUTS, clock_verification, grade_for
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
    """Independence is counted in telemetry sources, never in detector labels.

    Labelling two findings differently does not make them independent. A worm seen only through
    network telemetry and a burst seen only through egress are one source between them, and one
    source is one rung. Two sources still do not prove statistical independence: two sensors can
    share collection infrastructure.
    """
    live = [f for f in findings if f["grade"] != "unknown"]
    channels = {f["behaviour"] for f in live}
    independent_sources = {src for f in live for src in f.get("sources", [])}
    grade = grade_for(len(independent_sources))

    clocks = clock_verification(findings[0].get("_events", [])) if findings and findings[0].get("_events") else None
    limits = [l for f in live for l in f["limitations"]]
    limits.append("source labels do not establish statistical independence; two may share collection")
    limits.append("association is measured from each finding's anchor, so it is not transitive, "
                  "and observed proximity is not verified proximity")

    return {
        "grade": grade,
        "channels": sorted(channels),
        "independent_observations": len(independent_sources),
        "independent_sources": sorted(independent_sources),
        "techniques": sorted({t for f in live for t in f["techniques"]}),
        "affected_hosts": sorted({h for f in live for h in f.get("hosts", [])}),
        "observed": [o for f in live for o in f["observed"]],
        "alternatives": {f["behaviour"]: ALTERNATIVES.get(f["behaviour"], []) for f in live},
        "claims": {
            "source_independence": {"sources": sorted(independent_sources),
                                    "note": "distinct telemetry sources; this says nothing about clocks "
                                            "or about one incident"},
            "incident_association": {"anchor_rule": "every supporting observation is measured against the "
                                                    "finding's own anchor, never chained through another",
                                     "window_s": ASSOCIATION_WINDOW_S,
                                     "note": "same machine identity and window; this says nothing about "
                                             "clock reliability"},
            "temporal_reliability": clocks or {"basis": "observed",
                                               "note": "no clock evidence supplied for the hosts examined"},
        },
        "limitations": limits,
        "findings": findings,
        "chain": [{"behaviour": f["behaviour"], "first": f["observed"][0]} for f in live],
    }
