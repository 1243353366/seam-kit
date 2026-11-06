"""Shared vocabulary for the four engines. Nothing here decides a verdict on its own."""
from __future__ import annotations

LATERAL_PROTOCOLS = {"smb", "rdp", "ssh", "winrm", "wmi", "psremoting"}

#: Encryption is a write pattern before it is anything else.
BURST_FILES_PER_MINUTE = 60
BURST_WINDOW_S = 60.0
RENAME_BURST = 40

RECOVERY_MARKERS = ("shadow", "vss", "system restore", "snapshot", ".bak", "backup")
RECOVERY_CONFIG_KEYS = ("backup", "restore", "snapshot", "shadow", "recycle", "vss")

SIGNATURE_FREE_INPUTS = ["malware names", "file hashes", "vendor signatures", "file contents"]


def grade_for(independence: int) -> str:
    """Independent telemetry sources decide the grade. Nothing reaches confirmed from in here."""
    if independence >= 2:
        return "corroborated"
    if independence == 1:
        return "suspected"
    return "unknown"


def finding(behaviour: str, observations: list[str], limitations: list[str], techniques: list[str],
            sources: set[str], extra: dict | None = None) -> dict:
    """Independence is counted in *telemetry sources*, not observations.

    Two facts read from the same log are not corroboration. A write burst and a deleted shadow copy
    are both file metadata and count once between them; a burst plus egress counts twice.
    """
    independence = len(sources) if observations else 0
    out = {
        "behaviour": behaviour,
        "grade": grade_for(independence) if observations else "unknown",
        "observed": observations,
        "independent_channels": independence,
        "sources": sorted(sources) if observations else [],
        "techniques": list(techniques) if observations else [],
        "limitations": list(limitations),
    }
    if extra:
        out.update(extra)
    return out


#: Two observations belong to one incident only if they share a host and sit within this span.
#: Source diversity is not association: that was the previous correction, and this is the next one.
ASSOCIATION_WINDOW_S = 3600.0


def max_in_window(times: list[float], window: float) -> tuple[int, float]:
    """Largest count inside any `window`-long rolling span, and where that span starts.

    Fixed buckets have a boundary an attacker can straddle: 60 writes at 59.9s and 60.1s land in
    two buckets of 30 and neither reaches the threshold.
    """
    times = sorted(t for t in times)
    if not times:
        return 0, 0.0
    best, best_start, left = 0, times[0], 0
    for right, t in enumerate(times):
        while t - times[left] > window:
            left += 1
        if right - left + 1 > best:
            best, best_start = right - left + 1, times[left]
    return best, best_start


def identity_of(event: dict) -> str:
    """Stable machine identity when the sensor reports one, the hostname otherwise.

    A hostname is a label that imaging, cloning and reimaging all rewrite. `machine_id` is the
    sensor's own identity for the machine, so a rename mid-incident does not split the incident and
    two clones sharing a name do not merge into one.
    """
    machine = event.get("machine_id")
    if machine not in (None, ""):
        return f"machine:{str(machine).strip().lower()}"
    return f"host:{str(event.get('host', '')).strip().lower()}"


def identity_collisions(events: list[dict]) -> dict[str, set[str]]:
    """Hostnames reported by more than one machine: imaging, cloning or misconfiguration."""
    seen: dict[str, set[str]] = {}
    for e in events:
        if e.get("machine_id") in (None, ""):
            continue
        seen.setdefault(str(e["host"]).lower(), set()).add(str(e["machine_id"]).lower())
    return {host: ids for host, ids in seen.items() if len(ids) > 1}


def identity_migrations(events: list[dict]) -> dict[str, set[str]]:
    """One machine reported under more than one hostname: a rename or reimage mid-incident."""
    seen: dict[str, set[str]] = {}
    for e in events:
        if e.get("machine_id") in (None, ""):
            continue
        seen.setdefault(str(e["machine_id"]).lower(), set()).add(str(e["host"]).lower())
    return {machine: hosts for machine, hosts in seen.items() if len(hosts) > 1}


def same_identity(a: dict, b: dict) -> bool:
    if str(a.get("machine_id") or "") and str(b.get("machine_id") or ""):
        return identity_of(a) == identity_of(b)
    return str(a.get("host", "")).lower() == str(b.get("host", "")).lower()


def associated(items: list[dict], anchor: dict, at: float | None = None,
               window: float = ASSOCIATION_WINDOW_S) -> list[dict]:
    """Same machine identity, within the window measured from the anchor.

    Measured from the *anchor* every time, never from the nearest already-accepted event, so
    association cannot become transitive: two observations an hour apart on either side of the anchor
    are two hours apart from each other and never join.
    """
    target = float(anchor["at"] if at is None else at)
    return [e for e in items if same_identity(e, anchor) and abs(float(e["at"]) - target) <= window]


def clock_verification(events: list[dict]) -> dict:
    """Observed proximity versus verified proximity: separate claims, reported separately."""
    clocks = [e for e in events if e.get("kind") == "clock"]
    verified = [e for e in clocks if e.get("verified") is True]
    hosts = {e["host"] for e in events if e.get("kind") != "clock"}
    covered = {e["host"] for e in verified}
    offsets = [abs(float(e["offset_s"])) for e in verified if isinstance(e.get("offset_s"), (int, float))]
    return {
        "basis": "verified" if hosts and hosts <= covered else "observed",
        "verified_hosts": sorted(covered),
        "max_absolute_offset_s": max(offsets) if offsets else None,
        "unverified_hosts": sorted(hosts - covered),
    }
