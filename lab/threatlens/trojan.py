"""Trojans fail at execution and trust: ancestry, persistence, privilege and first contact."""
from __future__ import annotations

from ._common import LATERAL_PROTOCOLS, finding

BEHAVIOUR = "trojan_execution"

OFFICE_PARENTS = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "acrord32.exe", "preview"}
SHELLS = {"powershell.exe", "pwsh", "cmd.exe", "wscript.exe", "cscript.exe", "bash", "sh", "curl", "wget"}

#: Matched against a lower-cased, forward-slash normalised path.
AUTOSTART_MARKERS = (
    "/currentversion/run", "/currentversion/runonce", "/startup/", "/start menu/programs/startup",
    "/launchagents/", "/launchdaemons/", "/.config/systemd/user/", "/etc/cron.",
)


def analyse(events: list[dict], known_destinations: set[str] | None = None) -> dict:
    known = known_destinations or set()
    observations: list[str] = []
    sources: set[str] = set()

    odd = [e for e in events if e.get("kind") == "process"
           and str(e.get("parent", "")).lower() in OFFICE_PARENTS
           and str(e.get("image", "")).lower() in SHELLS]
    if odd:
        e = odd[0]
        observations.append(f"{e['parent']} spawned {e['image']} on {e['host']}")
        sources.add("process")

    persistence = [e for e in events if e.get("kind") == "file" and e.get("op") in ("write", "create")
                   and any(m in str(e.get("path", "")).lower().replace("\\", "/") for m in AUTOSTART_MARKERS)]
    if persistence:
        observations.append(f"write to an autostart location: {persistence[0]['path']}")
        sources.add("file")

    new_egress = [e for e in events if e.get("kind") == "network"
                  and e.get("proto") not in LATERAL_PROTOCOLS and known and e.get("dst") not in known]
    if new_egress:
        observations.append(f"first contact with {new_egress[0]['dst']} on {new_egress[0]['host']}")
        sources.add("network")

    escalations = [e for e in events if e.get("kind") == "privilege" and e.get("elevated") is True]
    if escalations and (odd or persistence):
        e = escalations[0]
        observations.append(f"{e.get('user', 'a process')} took elevated rights on {e['host']}"
                            " alongside the behaviour above")
        sources.add("privilege")

    signed = [e for e in events if e.get("kind") == "process" and e.get("signed")]
    limits = [
        "every shape here has a legitimate twin: installers spawn interpreters and write autostart keys",
        "a valid code signature proves who built the file, not what it does",
        "privilege events are self-reported by whatever produced the telemetry",
    ]
    if signed:
        limits.append(f"{len(signed)} participating process records were signed; that changes nothing here")

    return finding(BEHAVIOUR, observations, limits,
                   ["T1059 command interpreter", "T1547 autostart", "T1041 egress",
                    "T1068 privilege escalation"] if observations else [], sources)
