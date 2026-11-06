"""Ransomware fails at file access and operational control: bursts, renames, recovery, exposure."""
from __future__ import annotations

from collections import Counter

from lab.telemetry import extension

from ._common import BURST_FILES_PER_MINUTE, BURST_WINDOW_S, RECOVERY_CONFIG_KEYS, RECOVERY_MARKERS, RENAME_BURST, finding

BEHAVIOUR = "ransomware_impact"


def analyse(events: list[dict], egress_baseline: int | None = None) -> dict:
    writes = [e for e in events if e.get("kind") == "file" and e.get("op") in ("write", "create")]
    renames = [e for e in events if e.get("kind") == "file" and e.get("op") == "rename"]
    deletes = [e for e in events if e.get("kind") == "file" and e.get("op") == "delete"]
    configs = [e for e in events if e.get("kind") == "config"]

    per_minute: Counter[tuple[str, int]] = Counter()
    for e in writes:
        per_minute[(e["host"], int(float(e["at"]) // BURST_WINDOW_S))] += 1
    bursts = {k: v for k, v in per_minute.items() if v >= BURST_FILES_PER_MINUTE}
    rename_bursts = {h: n for h, n in Counter(e["host"] for e in renames).items() if n >= RENAME_BURST}

    observations: list[str] = []
    sources: set[str] = set()

    if bursts:
        (host, minute), n = max(bursts.items(), key=lambda kv: kv[1])
        observations.append(f"{n} file writes on {host} inside one minute (window {minute})")
        sources.add("file")
    if rename_bursts:
        host, n = max(rename_bursts.items(), key=lambda kv: kv[1])
        observations.append(f"{n} rename events on {host}")
        sources.add("file")

    churn = {extension(e.get("path", "")) for e in writes + renames} - {""}
    if bursts and len(churn) >= 3:
        observations.append(f"extensions churning across writes and renames: {', '.join(sorted(churn)[:4])}")
    elif bursts and len(churn) == 1 and churn:
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

    if egress_baseline is not None:
        out = sum(int(e.get("bytes", 0)) for e in events if e.get("kind") == "network")
        if egress_baseline and out > egress_baseline * 3:
            observations.append(f"egress {out / egress_baseline:.1f}x baseline before or during the burst")
            sources.add("network")

    if (bursts or rename_bursts) and (interference or weakened):
        observations.append("the burst and the recovery interference share a source, so they count once")

    limits = [
        "a bulk legitimate rewrite looks like this: a migration, an archive job, a sync client",
        "file contents are not examined, so encryption is inferred from pattern, not proven",
        "if data left before encryption, restoring the files does not resolve the exposure",
        "recovery interference is read from delete and config events, not from a volume that quietly stops",
    ]
    return finding(BEHAVIOUR, observations, limits,
                   ["T1486 data encrypted for impact", "T1490 inhibit system recovery"] if observations else [],
                   sources)
