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


def associated(items: list[dict], host: str, at: float, window: float = ASSOCIATION_WINDOW_S) -> list[dict]:
    """Same host, within the window. Everything else is a different incident sharing a report."""
    return [e for e in items if e.get("host") == host and abs(float(e.get("at", 0.0)) - at) <= window]
