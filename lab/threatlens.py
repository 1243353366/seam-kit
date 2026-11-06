"""THREAT-LENS: behaviour, not names.

Four threat classes fail in different places, so they get four analysers rather than one detector:

  worm        fails at propagation, so it is visible in fan-out, repeat attempts and service creation
  trojan      fails at execution and trust, so it is visible in ancestry, persistence and new egress
  software    fails at vendor and dependency trust, so it is visible as drift from a verified baseline
  ransomware  fails at file access and operational control, so it is visible as write bursts,
              egress before impact and interference with recovery

No analyser takes a malware name, a file hash or a vendor signature as input. Those are reputation,
not behaviour, and reputation is what the operator already has. What is graded here is what something
did and which independent channels agree it did it.

Grading keeps the discipline the rest of the repo uses: one channel is `suspected`, two independent
channels are `corroborated`, and nothing here is ever `confirmed`. Confirmation is an examiner
determination backed by a record kept outside the machine under examination.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

#: Parents that should not be starting an interpreter or a downloader.
OFFICE_PARENTS = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "acrord32.exe", "preview"}
SHELLS = {"powershell.exe", "pwsh", "cmd.exe", "wscript.exe", "cscript.exe", "bash", "sh", "curl", "wget"}

#: Persistence locations, across the platforms this lab pretends to cover.
#: Matched against a lower-cased, forward-slash normalised path.
AUTOSTART_MARKERS = (
    "/currentversion/run",
    "/currentversion/runonce",
    "/startup/",
    "/start menu/programs/startup",
    "/launchagents/",
    "/launchdaemons/",
    "/.config/systemd/user/",
    "/etc/cron.",
)

LATERAL_PROTOCOLS = {"smb", "rdp", "ssh", "winrm", "wmi", "psremoting"}

#: Encryption is a write pattern before it is anything else.
BURST_FILES_PER_MINUTE = 60
BURST_WINDOW_S = 60.0

RECOVERY_MARKERS = ("shadow", "vss", "system restore", "snapshot", ".bak", "backup")


def _grade_for(independence: int) -> str:
    """Independent channels decide the grade. Nothing reaches confirmed from inside one machine."""
    if independence >= 2:
        return "corroborated"
    if independence == 1:
        return "suspected"
    return "unknown"


def _finding(behaviour: str, observations: list[str], limitations: list[str], techniques: list[str],
             sources: set[str], extra: dict | None = None) -> dict:
    """Independence is counted in *telemetry sources*, not observations.

    Two facts read from the same log are not corroboration. A write burst and a deleted shadow copy
    are both file metadata, so they count once between them; a burst plus egress counts twice.
    """
    independence = len(sources) if observations else 0
    out = {
        "behaviour": behaviour,
        "grade": _grade_for(independence) if observations else "unknown",
        "observed": observations,
        "independent_channels": independence,
        "sources": sorted(sources) if observations else [],
        "techniques": techniques,
        "limitations": limitations,
    }
    if extra:
        out.update(extra)
    return out


# ------------------------------------------------------------------------ worm ---
def analyse_worm(events: list[dict]) -> dict:
    """Propagation leaves fan-out, repeats and service creation. Each is a separate channel."""
    lateral = [e for e in events if e.get("kind") == "network" and e.get("proto") in LATERAL_PROTOCOLS]
    services = [e for e in events if e.get("kind") == "service" and e.get("state") == "created"]

    fanout: dict[str, set[str]] = defaultdict(set)
    repeats: Counter[tuple[str, str]] = Counter()
    for e in lateral:
        fanout[e["host"]].add(e["dst"])
        repeats[(e["host"], e["dst"])] += 1

    spreaders = {h: dsts for h, dsts in fanout.items() if len(dsts) >= 3}
    repeated = {k: n for k, n in repeats.items() if n >= 3}

    observations, independence, sources = [], 0, set()
    if spreaders:
        worst = max(spreaders, key=lambda h: len(spreaders[h]))
        observations.append(f"{worst} opened {len(spreaders[worst])} lateral connections to distinct hosts")
        independence += 1
        sources.add("network")
    if repeated:
        (src, dst), n = max(repeated.items(), key=lambda kv: kv[1])
        observations.append(f"{n} repeated attempts from {src} to {dst}")
        independence += 1
        sources.add("network")
    if services:
        hosts = {e["host"] for e in services}
        if len(hosts) >= 2:
            observations.append(f"services created on {len(hosts)} hosts: {', '.join(sorted(hosts)[:4])}")
            independence += 1
            sources.add("service")

    limits = [
        "fan-out is also what a deployment tool, a backup agent or a vulnerability scanner produces",
        "the window supplied bounds what can be seen; silence outside it is not evidence",
    ]
    return _finding(
        "worm_propagation",
        observations,
        limits,
        ["T1021 remote services", "T1570 lateral tool transfer"] if observations else [],
        sources,
        {"hosts": sorted(spreaders)},
    )


# ---------------------------------------------------------------------- trojan ---
def analyse_trojan(events: list[dict], known_destinations: set[str] | None = None) -> dict:
    """Execution and trust fail visibly: ancestry, persistence, and where it talks."""
    known = known_destinations or set()
    observations, independence, sources = [], 0, set()

    odd_children = [
        e for e in events
        if e.get("kind") == "process"
        and str(e.get("parent", "")).lower() in OFFICE_PARENTS
        and str(e.get("image", "")).lower() in SHELLS
    ]
    if odd_children:
        e = odd_children[0]
        observations.append(f"{e['parent']} spawned {e['image']} on {e['host']}")
        independence += 1
        sources.add("process")

    persistence = [
        e for e in events
        if e.get("kind") == "file" and e.get("op") == "write"
        and any(m in str(e.get("path", "")).lower().replace("\\", "/") for m in AUTOSTART_MARKERS)
    ]
    if persistence:
        observations.append(f"write to an autostart location: {persistence[0]['path']}")
        independence += 1
        sources.add("file")

    new_egress = [
        e for e in events
        if e.get("kind") == "network" and e.get("proto") not in LATERAL_PROTOCOLS
        and known and e.get("dst") not in known
    ]
    if new_egress:
        observations.append(f"first contact with {new_egress[0]['dst']} on {new_egress[0]['host']}")
        independence += 1
        sources.add("network")

    signed = [e for e in egress_signed(events)]
    limits = [
        "every shape here has a legitimate twin: installers spawn interpreters and write autostart keys",
        "a valid code signature proves who built the file, not what it does",
    ]
    if signed:
        limits.append(f"{len(signed)} participating binary/binaries were signed; that changes nothing here")

    return _finding(
        "trojan_execution",
        observations,
        limits,
        ["T1059 command interpreter", "T1547 autostart", "T1041 egress"] if observations else [],
        sources,
    )


def egress_signed(events: list[dict]) -> list[dict]:
    return [e for e in events if e.get("kind") == "process" and e.get("signed")]


# -------------------------------------------------------------------- software ---
def analyse_software_integrity(baseline: dict, observed: dict) -> dict:
    """Can an installed application be shown to behave differently from its verified baseline?"""
    observations, independence, sources = [], 0, set()

    if baseline.get("binary_digest") and observed.get("binary_digest") != baseline.get("binary_digest"):
        observations.append("installed binary digest differs from the recorded baseline")
        independence += 1
        sources.add("binary")
    if observed.get("version") and baseline.get("version") and observed["version"] < baseline["version"]:
        observations.append(f"version moved backwards: {baseline['version']} -> {observed['version']}")
        independence += 1
        sources.add("binary")
    new_dst = sorted(set(observed.get("destinations", [])) - set(baseline.get("destinations", [])))
    if new_dst:
        observations.append(f"new destinations: {', '.join(new_dst[:3])}")
        independence += 1
        sources.add("network")
    base_telemetry = baseline.get("telemetry_bytes") or 0
    obs_telemetry = observed.get("telemetry_bytes") or 0
    if base_telemetry and obs_telemetry > base_telemetry * 3:
        observations.append(f"telemetry volume {obs_telemetry / base_telemetry:.1f}x baseline")
        independence += 1
        sources.add("network")

    limits = [
        "a changed digest is an observation, not an accusation: updates change digests by design",
        "the baseline is only as trustworthy as the machine that recorded it",
        "without an SBOM, dependencies shipped inside the match are invisible",
    ]
    return _finding(
        "software_drift", observations, limits,
        ["T1195 supply chain compromise"] if observations else [], sources,
    )


# ------------------------------------------------------------------- ransomware ---
def analyse_ransomware(events: list[dict], egress_baseline: int | None = None) -> dict:
    """Encryption is a write pattern, recovery interference is a delete pattern."""
    writes = [e for e in events if e.get("kind") == "file" and e.get("op") == "write"]
    deletes = [e for e in events if e.get("kind") == "file" and e.get("op") == "delete"]

    per_minute: Counter[tuple[str, int]] = Counter()
    for e in writes:
        per_minute[(e["host"], int(float(e.get("at", 0)) // BURST_WINDOW_S))] += 1
    bursts = {k: v for k, v in per_minute.items() if v >= BURST_FILES_PER_MINUTE}

    observations, independence, sources = [], 0, set()
    if bursts:
        (host, minute), n = max(bursts.items(), key=lambda kv: kv[1])
        observations.append(f"{n} file writes on {host} inside one minute (window {minute})")
        independence += 1  # file metadata
        sources.add("file")

    interference = [
        e for e in deletes
        if any(m in str(e.get("path", "")).lower().replace("\\", "/") for m in RECOVERY_MARKERS)
    ]
    if interference:
        observations.append(f"recovery artefact deleted: {interference[0]['path']}")
        independence += 1
        sources.add("file")

    if egress_baseline is not None:
        out = sum(int(e.get("bytes", 0)) for e in events if e.get("kind") == "network")
        if out > egress_baseline * 3:
            observations.append(f"egress {out / egress_baseline:.1f}x baseline before or during the burst")
            independence += 1
            sources.add("network")

    if interference and bursts:
        observations.append("both observations come from file metadata, so together they are one source")
    limits = [
        "a bulk legitimate rewrite looks like this: a migration, an archive job, a sync client",
        "file contents are not examined, so encryption is inferred from pattern, not proven",
        "if data left before encryption, restoring the files does not resolve the exposure",
    ]
    return _finding(
        "ransomware_impact", observations, limits,
        ["T1486 data encrypted for impact", "T1490 inhibit system recovery"] if observations else [],
        sources,
    )


# ------------------------------------------------------------------ correlate ---
def correlate(findings: list[dict]) -> dict:
    """One incident from several channels, ordered by time of first observation."""
    live = [f for f in findings if f["grade"] != "unknown"]
    channels = {f["behaviour"] for f in live}
    independence = sum(f["independent_channels"] for f in live)
    grades = [f["grade"] for f in live]
    # Two behaviours seen through different sources, or one behaviour confirmed through two sources.
    # Never more than that from inside the machine.
    if any(g == "corroborated" for g in grades) or len(channels) >= 2:
        grade = "corroborated"
    elif grades:
        grade = "suspected"
    else:
        grade = "unknown"

    techniques = sorted({t for f in live for t in f["techniques"]})
    hosts = sorted({h for f in live for h in f.get("hosts", [])})
    limits = [l for f in live for l in f["limitations"]]
    limits.append("correlation here is by host and time only: no shared clock discipline is enforced")

    return {
        "grade": grade,
        "channels": sorted(channels),
        "independent_observations": independence,
        "techniques": techniques,
        "affected_hosts": hosts,
        "observed": [o for f in live for o in f["observed"]],
        "limitations": limits,
        "chain": sorted(
            ({"behaviour": f["behaviour"], "first": f["observed"][0]} for f in live),
            key=lambda x: x["behaviour"],
        ),
    }


def investigate(events: list[dict], *, baseline: dict | None = None,
                observed_software: dict | None = None, known_destinations: set[str] | None = None,
                egress_baseline: int | None = None) -> dict:
    """Run every analyser that has the inputs for it, then correlate. Signature-free by design."""
    findings = [
        analyse_worm(events),
        analyse_trojan(events, known_destinations),
        analyse_ransomware(events, egress_baseline),
    ]
    if baseline and observed_software:
        findings.append(analyse_software_integrity(baseline, observed_software))

    report = correlate(findings)
    report.update({
        "signature_free": True,
        "inputs_used": sorted({"process", "network", "file", "service"} & {e.get("kind") for e in events}),
        "inputs_not_used": ["malware names", "file hashes", "vendor signatures", "file contents"],
        "findings": findings,
        "confirmed": False,
        "note": "confirmation is an examiner determination, and requires a record kept off the machine",
    })
    return report


def to_markdown(report: dict) -> str:
    lines = [f"# THREAT-LENS report", "", f"Overall grade: **{report['grade']}**", ""]
    lines.append("| behaviour | grade | independent channels | observed |")
    lines.append("| --- | --- | --- | --- |")
    for f in report["findings"]:
        seen = "; ".join(f["observed"]) or "-"
        lines.append(f"| {f['behaviour']} | {f['grade']} | {f['independent_channels']} | {seen} |")
    lines.append("")
    lines.append("## What would still be true if the software were renamed")
    lines.append("Nothing here reads a name, a hash or a vendor. `inputs_not_used`: "
                 + ", ".join(report["inputs_not_used"]) + ".")
    lines.append("")
    lines.append("## Limits")
    for limit in report["limitations"]:
        lines.append(f"- {limit}")
    return "\n".join(lines) + "\n"
