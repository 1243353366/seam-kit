"""Commercial software fails at vendor and dependency trust, so the baseline is the instrument."""
from __future__ import annotations

import re

from ._common import finding

BEHAVIOUR = "software_drift"


def numeric_version(value: str) -> tuple[int, ...] | None:
    """Parse dotted numerics. String order puts 4.10 before 4.9, which is wrong and dangerous."""
    if not isinstance(value, str) or not re.fullmatch(r"\d+(?:\.\d+)*", value.strip()):
        return None
    return tuple(int(part) for part in value.strip().split("."))


def analyse(baseline: dict, observed: dict) -> dict:
    observations: list[str] = []
    sources: set[str] = set()

    if baseline.get("binary_digest") and observed.get("binary_digest") != baseline.get("binary_digest"):
        observations.append("installed binary digest differs from the recorded baseline")
        sources.add("binary")
    if observed.get("publisher") and baseline.get("publisher") \
            and observed["publisher"] != baseline["publisher"]:
        observations.append(f"publisher changed: {baseline['publisher']} -> {observed['publisher']}")
        sources.add("binary")
    base_v = numeric_version(str(baseline.get("version") or ""))
    obs_v = numeric_version(str(observed.get("version") or ""))
    version_note = None
    if base_v is not None and obs_v is not None:
        if obs_v < base_v:
            observations.append(f"version moved backwards: {baseline['version']} -> {observed['version']}")
            sources.add("binary")
    elif baseline.get("version") or observed.get("version"):
        version_note = (f"version ordering unavailable: {baseline.get('version')!r} -> "
                        f"{observed.get('version')!r} is not a dotted numeric")

    added = sorted(set(observed.get("dependencies", [])) - set(baseline.get("dependencies", [])))
    if added:
        observations.append(f"new bundled dependencies: {', '.join(added[:3])}")
        sources.add("dependency")

    new_dst = sorted(set(observed.get("destinations", [])) - set(baseline.get("destinations", [])))
    if new_dst:
        observations.append(f"new destinations: {', '.join(new_dst[:3])}")
        sources.add("network")
    base_tel = baseline.get("telemetry_bytes") or 0
    obs_tel = observed.get("telemetry_bytes") or 0
    if base_tel and obs_tel > base_tel * 3:
        observations.append(f"telemetry volume {obs_tel / base_tel:.1f}x baseline")
        sources.add("network")

    privileged = [s for s in observed.get("services", []) if s.get("privileged")]
    base_services = {s.get("name") for s in baseline.get("services", [])}
    new_priv = [s for s in privileged if s.get("name") not in base_services]
    if new_priv:
        observations.append(f"new privileged service: {new_priv[0].get('name')}")
        sources.add("config")

    limits = [
        "a changed digest is an observation, not an accusation: updates change digests by design",
        "the baseline is only as trustworthy as the machine that recorded it",
        "without an SBOM, dependencies shipped inside the match are invisible",
        "publisher strings are self-declared and are not identities",
    ]
    if version_note:
        limits.append(version_note)
    return finding(BEHAVIOUR, observations, limits,
                   ["T1195 supply chain compromise", "T1543 create or modify system service"]
                   if observations else [], sources)
