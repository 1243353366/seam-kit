"""The evidence record. A finding that reads 'DETECTED' is a finding nobody can defend."""
from __future__ import annotations

NO_REVIEW = "no behaviour requiring examiner review in the events supplied"

CONCLUSIONS = {
    "corroborated": "behaviour requiring examiner review; two or more telemetry sources agree",
    "suspected": "behaviour requiring examiner review; one telemetry source observed it",
    "unknown": NO_REVIEW,
}


def evidence_record(case: str, host: str, report: dict, alternatives: dict | None = None) -> dict:
    """Join a correlation report to a case, so it can be stored beside the media findings."""
    live = [f for f in report["findings"] if f["grade"] != "unknown"]
    alts = alternatives or report.get("alternatives", {})
    return {
        "case": case,
        "host": host,
        "grade": report["grade"],
        "findings": [
            {"behaviour": f["behaviour"], "grade": f["grade"], "observed": f["observed"],
             "sources": f["sources"], "techniques": f["techniques"],
             "alternative_explanations": alts.get(f["behaviour"], [])}
            for f in live
        ],
        "corroboration": {f["behaviour"]: f["sources"] for f in live},
        "conclusion": CONCLUSIONS[report["grade"]],
        "confirmed": False,
        "signature_free": True,
        "inputs_not_used": list(report.get("inputs_not_used", [])),
        "limitations": report["limitations"],
        "next_step": "preserve the source telemetry and hand to an examiner; nothing here is a conclusion",
    }


def as_text(record: dict) -> str:
    lines = [f"Case: {record['case']}", f"Host: {record['host']}", f"Grade: {record['grade']}", ""]
    for f in record["findings"]:
        lines.append(f"Finding: {f['behaviour'].replace('_', ' ')} ({f['grade']})")
        lines.append("Observed:")
        lines += [f"- {o}" for o in f["observed"]] or ["- nothing"]
        lines.append("Corroboration:")
        lines += [f"- {s} telemetry" for s in f["sources"]] or ["- none"]
        lines.append("Alternative explanations:")
        lines += [f"- {a}" for a in f["alternative_explanations"]] or ["- none considered"]
        lines.append("")
    lines.append(f"Conclusion:\n{record['conclusion']}")
    lines.append("")
    lines.append("Limits:")
    lines += [f"- {l}" for l in record["limitations"]]
    return "\n".join(lines) + "\n"
