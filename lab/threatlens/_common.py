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
