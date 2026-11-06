"""Ransomware fails at file access and operational control: bursts, renames, recovery, exposure."""
from __future__ import annotations

from ._common import LATERAL_PROTOCOLS

from lab.telemetry import by_host, extension, sorted_events

from ._common import (ASSOCIATION_WINDOW_S, BURST_FILES_PER_MINUTE, BURST_WINDOW_S, RECOVERY_CONFIG_KEYS,
                      RECOVERY_MARKERS, RENAME_BURST, associated, finding, identity_collisions,
                      identity_migrations, identity_of, max_in_window)

BEHAVIOUR = "ransomware_impact"


def _by_identity(events: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for e in events:
        out.setdefault(identity_of(e), []).append(e)
    return out


def analyse(events: list[dict], egress_baseline: int | None = None) -> dict:
    events = sorted_events(events)
    writes = [e for e in events if e.get("kind") == "file" and e.get("op") in ("write", "create")]
    renames = [e for e in events if e.get("kind") == "file" and e.get("op") == "rename"]
    deletes = [e for e in events if e.get("kind") == "file" and e.get("op") == "delete"]
    configs = [e for e in events if e.get("kind") == "config"]

    def busiest(group: list[dict]) -> tuple[dict | None, int, float]:
        best, count, start = None, 0, 0.0
        for _, evs in _by_identity(group).items():
            found, when = max_in_window([e["at"] for e in evs], BURST_WINDOW_S)
            if found > count:
                best, count, start = evs[0], found, when
        return best, count, start

    burst_anchor, burst_count, burst_at = busiest(writes)
    rename_anchor, rename_count, rename_at = busiest(renames)

    # One incident: the anchor machine and the anchor's own clock. Supporting events elsewhere are a
    # different incident that happens to share a report.
    anchor = burst_anchor or rename_anchor
    scope_at = burst_at if burst_anchor else rename_at
    scope_host = anchor["host"] if anchor else ""
    scope_id = identity_of(anchor) if anchor else ""
    network = [e for e in events if e.get("kind") == "network"]
    orphans = 0
    if anchor:
        for group in (deletes, configs, network):
            orphans += len(group) - len(associated(group, anchor, scope_at))
    deletes = associated(deletes, anchor, scope_at) if anchor else []
    configs = associated(configs, anchor, scope_at) if anchor else []

    observations: list[str] = []
    sources: set[str] = set()

    if burst_count >= BURST_FILES_PER_MINUTE:
        observations.append(f"{burst_count} file writes on {burst_anchor['host']} "
                            f"within {BURST_WINDOW_S:.0f}s")
        sources.add("file")
    if rename_count >= RENAME_BURST:
        observations.append(f"{rename_count} rename events on {rename_anchor['host']} "
                            f"within {BURST_WINDOW_S:.0f}s")
        sources.add("file")

    churn = {extension(e.get("path", "")) for e in writes + renames if identity_of(e) == scope_id} - {""}
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
        outbound = associated(network, anchor, scope_at) if anchor else []
        outbound = [e for e in outbound if e.get("proto") not in LATERAL_PROTOCOLS]
        out = sum(int(e.get("bytes", 0)) for e in outbound)
        if egress_baseline > 0:
            if out > egress_baseline * 3:
                observations.append(f"egress {out / egress_baseline:.1f}x baseline on {scope_host} "
                                    f"within {ASSOCIATION_WINDOW_S:.0f}s of the anchor")
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
    limits.append("association is a machine identity and a window measured from the anchor, "
                  "not a proven causal link, and it is deliberately not transitive")
    collisions = identity_collisions(events)
    if collisions:
        host = sorted(collisions)[0]
        limits.append(f"host identity collision: {len(collisions[host])} machines report the name {host}")
    migrations = identity_migrations(events)
    if migrations:
        machine = sorted(migrations)[0]
        limits.append(f"machine {machine} appears as {', '.join(sorted(migrations[machine]))}: "
                      "a rename keeps one incident")
    return finding(BEHAVIOUR, observations, limits,
                   ["T1486 data encrypted for impact", "T1490 inhibit system recovery"] if observations else [],
                   sources)
