"""Ransomware fails at file access and operational control: bursts, renames, recovery, exposure."""
from __future__ import annotations

from ._common import LATERAL_PROTOCOLS

from lab.telemetry import by_host, extension, sorted_events

from ._common import (ASSOCIATION_WINDOW_S, BURST_FILES_PER_MINUTE, BURST_WINDOW_S, RECOVERY_CONFIG_KEYS,
                      RECOVERY_MARKERS, RENAME_BURST, associated, finding, max_in_window)

BEHAVIOUR = "ransomware_impact"


def analyse(events: list[dict], egress_baseline: int | None = None) -> dict:
    events = sorted_events(events)
    writes = [e for e in events if e.get("kind") == "file" and e.get("op") in ("write", "create")]
    renames = [e for e in events if e.get("kind") == "file" and e.get("op") == "rename"]
    deletes = [e for e in events if e.get("kind") == "file" and e.get("op") == "delete"]
    configs = [e for e in events if e.get("kind") == "config"]

    burst_host, burst_count, burst_at = "", 0, 0.0
    for host, evs in by_host(writes).items():
        count, start = max_in_window([e["at"] for e in evs], BURST_WINDOW_S)
        if count > burst_count:
            burst_host, burst_count, burst_at = host, count, start
    rename_host, rename_count, rename_at = "", 0, 0.0
    for host, evs in by_host(renames).items():
        count, start = max_in_window([e["at"] for e in evs], BURST_WINDOW_S)
        if count > rename_count:
            rename_host, rename_count, rename_at = host, count, start

    # One incident: the burst host and the burst's own clock. Supporting events elsewhere are a
    # different incident that happens to share a report.
    scope_host = burst_host or rename_host
    scope_at = burst_at if burst_host else rename_at
    orphans = 0
    if scope_host:
        for group in (deletes, configs, [e for e in events if e.get("kind") == "network"]):
            orphans += len(group) - len(associated(group, scope_host, scope_at))
    deletes = associated(deletes, scope_host, scope_at) if scope_host else []
    configs = associated(configs, scope_host, scope_at) if scope_host else []

    observations: list[str] = []
    sources: set[str] = set()

    if burst_count >= BURST_FILES_PER_MINUTE:
        observations.append(f"{burst_count} file writes on {burst_host} within {BURST_WINDOW_S:.0f}s")
        sources.add("file")
    if rename_count >= RENAME_BURST:
        observations.append(f"{rename_count} rename events on {rename_host} within {BURST_WINDOW_S:.0f}s")
        sources.add("file")

    churn = {extension(e.get("path", "")) for e in writes + renames if e["host"] == scope_host} - {""}
    if burst_count >= BURST_FILES_PER_MINUTE and len(churn) >= 3:
        observations.append(f"extensions churning across writes and renames: {', '.join(sorted(churn)[:4])}")
    elif burst_count >= BURST_FILES_PER_MINUTE and len(churn) == 1 and churn:
        observations.append(f"a single unexpected extension dominates: {churn.pop()}")

    interference = [e for e in deletes
                    if any(m in str(e.get("path", "")).lower().replace("\\", "/") for m in RECOVERY_MARKERS)]
    if interference:
        observations.append(f"recovery artefact deleted: {interference[0]['path']}")
        sources.add("file")

    weakened = [c for c in configs if any(m in str(c.get("key", "")).lower() for m in RECOVERY_CONFIG_KEYS)
                and c.get("op") in ("modify", "delete", "disable")]
    if weakened:
        observations.append(f"recovery configuration changed: {weakened[0].get('key')} {weakened[0].get('op')}")
        sources.add("config")

    egress_note = None
    if egress_baseline is not None:
        outbound = associated([e for e in events if e.get("kind") == "network"], scope_host, scope_at) \
            if scope_host else []
        outbound = [e for e in outbound if e.get("proto") not in LATERAL_PROTOCOLS]
        out = sum(int(e.get("bytes", 0)) for e in outbound)
        if egress_baseline > 0:
            if out > egress_baseline * 3:
                observations.append(f"egress {out / egress_baseline:.1f}x baseline on {scope_host} "
                                    f"within {ASSOCIATION_WINDOW_S:.0f}s of the burst")
                sources.add("network")
        else:
            egress_note = f"egress comparison skipped: baseline {egress_baseline} is not positive"

    shared_note = None
    if (burst_count >= BURST_FILES_PER_MINUTE or rename_count >= RENAME_BURST) and (interference or weakened):
        shared_note = "write burst and recovery interference are both file metadata, so they count once"

    limits = [
        "a bulk legitimate rewrite looks like this: a migration, an archive job, a sync client",
        "file contents are not examined, so encryption is inferred from pattern, not proven",
        "if data left before encryption, restoring the files does not resolve the exposure",
        "recovery interference is read from delete and config events, not from a volume that quietly stops",
    ]
    if shared_note:
        limits.append(shared_note)
    if egress_note:
        limits.append(egress_note)
    if orphans:
        limits.append(f"{orphans} supporting events were on other hosts or outside the window and were not associated")
    limits.append("association is a host and a time window, not a proven causal link")
    return finding(BEHAVIOUR, observations, limits,
                   ["T1486 data encrypted for impact", "T1490 inhibit system recovery"] if observations else [],
                   sources)
