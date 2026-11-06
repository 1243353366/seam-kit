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


#: Clock evidence older or newer than this relative to an anchor says nothing about that anchor.
CLOCK_VALIDITY_S = 3600.0


def machine_id_of(event: dict) -> str | None:
    machine = event.get("machine_id")
    if machine is None or isinstance(machine, bool):
        return None
    text = str(machine).strip().lower()
    return text or None


def identity_of(event: dict) -> str:
    """Stable machine identity when the sensor reports one, the hostname otherwise.

    A hostname is a label that imaging, cloning and reimaging all rewrite. `machine_id` is the
    sensor's own identity for the machine, so a rename mid-incident does not split the incident and
    two clones sharing a name do not merge into one.
    """
    machine = machine_id_of(event)
    if machine:
        return f"machine:{machine}"
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


class Identity:
    """Who is who, and which hostnames are no longer able to answer that question.

    A hostname that appears with two machine identities is a clone or a misconfiguration. Once that
    is known, an event carrying no identity on that hostname cannot be attributed to either machine,
    so it is refused rather than matched by name.
    """

    def __init__(self, events: list[dict]):
        self.collisions = identity_collisions(events)
        self.migrations = identity_migrations(events)

    def ambiguous(self, event: dict) -> bool:
        return (machine_id_of(event) is None
                and str(event.get("host", "")).lower() in self.collisions)

    def same(self, a: dict, b: dict) -> bool:
        left, right = machine_id_of(a), machine_id_of(b)
        if left and right:
            return left == right
        if str(a.get("host", "")).lower() != str(b.get("host", "")).lower():
            return False
        return not (self.ambiguous(a) or self.ambiguous(b))


def same_identity(a: dict, b: dict) -> bool:
    """Pairwise identity with no context. Prefer `Identity.same`, which knows about collisions."""
    return Identity([a, b]).same(a, b)


def associated(items: list[dict], anchor: dict, at: float | None = None,
               window: float = ASSOCIATION_WINDOW_S, index: "Identity | None" = None) -> list[dict]:
    """Same machine identity, within the window measured from the anchor.

    Measured from the *anchor* every time, never from the nearest already-accepted event, so
    association cannot become transitive: two observations an hour apart on either side of the anchor
    are two hours apart from each other and never join.
    """
    target = float(anchor["at"] if at is None else at)
    idx = index or Identity(items + [anchor])
    return [e for e in items if idx.same(e, anchor) and abs(float(e["at"]) - target) <= window]


def clock_verification(events: list[dict], anchors: list[dict] | None = None) -> dict:
    """Observed proximity versus verified proximity: separate claims, reported separately.

    `verified: true` from the same untrusted stream is an assertion, so a clock event only counts when
    it names an independent attestation and sits inside `CLOCK_VALIDITY_S` of the anchor it is meant to
    support. Coverage is per machine identity, not per hostname: one clock on one of two clones covers
    one clone.
    """
    anchors = anchors or []
    idx = Identity(events)
    # Every machine whose timestamps the report leans on, not just the ones with findings: a
    # `verified` badge over a stream containing unwitnessed clocks would be a lie by omission.
    relevant = {identity_of(e) for e in events if e.get("kind") != "clock"} | {identity_of(a) for a in anchors}
    reference: dict[str, dict] = {}
    for event in [e for e in events if e.get("kind") != "clock"]:
        current = reference.get(identity_of(event))
        if current is None or float(event["at"]) < float(current["at"]):
            reference[identity_of(event)] = event
    for anchor in anchors:
        reference.setdefault(identity_of(anchor), anchor)
    covered: set[str] = set()
    offsets: list[float] = []
    attestations: set[str] = set()
    rejected = {"unverified": 0, "unattested": 0, "stale": 0, "ambiguous": 0}

    for clock in (e for e in events if e.get("kind") == "clock"):
        if clock.get("verified") is not True:
            rejected["unverified"] += 1
            continue
        attestation = str(clock.get("attested_by") or "").strip()
        if not attestation:
            rejected["unattested"] += 1
            continue
        if idx.ambiguous(clock):
            rejected["ambiguous"] += 1
            continue
        known = reference.get(identity_of(clock))
        if known is None:
            continue  # a clock for a machine that contributes no events is not coverage
        if abs(float(clock["at"]) - float(known["at"])) > CLOCK_VALIDITY_S:
            rejected["stale"] += 1
            continue
        covered.add(identity_of(clock))
        attestations.add(attestation)
        if isinstance(clock.get("offset_s"), (int, float)):
            offsets.append(abs(float(clock["offset_s"])))

    return {
        "basis": "verified" if relevant and relevant <= covered else "observed",
        "verified_identities": sorted(covered),
        "unverified_identities": sorted(relevant - covered),
        "max_absolute_offset_s": max(offsets) if offsets else None,
        "attested_by": sorted(attestations),
        "rejected_clock_events": {k: v for k, v in rejected.items() if v},
        "validity_window_s": CLOCK_VALIDITY_S,
        "note": "verified needs an independently attested clock, on that machine identity, inside "
                "the validity window; a bare boolean is an assertion",
    }
