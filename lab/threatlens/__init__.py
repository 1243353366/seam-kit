"""THREAT-LENS: four threat classes, four failure points, three shared rules.

Rules: no engine takes a name, a hash, a signature or file contents; independence is counted in
telemetry sources rather than observations; nothing from inside the machine is ever `confirmed`.
"""
from __future__ import annotations

from lab import telemetry

from . import ransomware as _ransomware, software as _software, trojan as _trojan, worm as _worm
from . import _common
from ._common import SIGNATURE_FREE_INPUTS
from .correlate import ALTERNATIVES, correlate
from .record import as_text, evidence_record

analyse_worm = _worm.analyse
analyse_trojan = _trojan.analyse
analyse_software_integrity = _software.analyse
analyse_ransomware = _ransomware.analyse
pattern_similarity = _worm.pattern_similarity

__all__ = [
    "ALTERNATIVES", "SIGNATURE_FREE_INPUTS", "analyse_ransomware", "analyse_software_integrity",
    "analyse_trojan", "analyse_worm", "as_text", "correlate", "evidence_record", "investigate",
    "pattern_similarity", "to_markdown",
]


def investigate(events: list[dict], *, baseline: dict | None = None,
                observed_software: dict | None = None, known_destinations: set[str] | None = None,
                egress_baseline: int | None = None, strict: bool = False) -> dict:
    """Run every engine that has the inputs for it, then correlate. Signature-free by design."""
    schema_problems = telemetry.problems(events)
    if schema_problems and strict:
        telemetry.check(events)

    # Validate per event. The old fallback kept malformed events whenever anything looked wrong, so
    # one bad row turned into a KeyError inside an engine instead of a controlled result.
    clean = [telemetry.normalise(e) for e in events
             if isinstance(e, dict) and not telemetry.problems([e])]

    findings = [_worm.analyse(clean), _trojan.analyse(clean, known_destinations),
                _ransomware.analyse(clean, egress_baseline)]
    if baseline and observed_software:
        findings.append(_software.analyse(baseline, observed_software))

    report = correlate(findings)
    anchors = [f["anchor"] for f in report["findings"] if f.get("anchor")]
    report["claims"]["temporal_reliability"] = _common.clock_verification(clean, anchors)
    report.update({
        "signature_free": True,
        "schema_problems": schema_problems,
        "events_examined": len(clean),
        "events_rejected": len(events) - len(clean),
        "inputs_used": sorted({e.get("kind") for e in clean if e.get("kind")}),
        "inputs_not_used": list(SIGNATURE_FREE_INPUTS),
        "confirmed": False,
        "note": "confirmation is an examiner determination, and requires a record kept off the machine",
    })
    return report


def to_markdown(report: dict) -> str:
    lines = ["# THREAT-LENS report", "", f"Overall grade: **{report['grade']}**", ""]
    lines.append("| behaviour | grade | sources | observed |")
    lines.append("| --- | --- | --- | --- |")
    for f in report["findings"]:
        lines.append(f"| {f['behaviour']} | {f['grade']} | {', '.join(f['sources']) or '-'} | "
                     f"{'; '.join(f['observed']) or '-'} |")
    lines.append("")
    lines.append("## Alternative explanations")
    for behaviour, alts in report["alternatives"].items():
        lines.append(f"- **{behaviour}**: " + ("; ".join(alts) if alts else "none considered"))
    lines.append("")
    lines.append("## What would still be true if the software were renamed")
    lines.append("Nothing here reads a name, a hash or a vendor. `inputs_not_used`: "
                 + ", ".join(report["inputs_not_used"]) + ".")
    lines.append("")
    lines.append("## Limits")
    for limit in report["limitations"]:
        lines.append(f"- {limit}")
    return "\n".join(lines) + "\n"
