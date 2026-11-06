"""Benign event generators. No malware, no binaries, no network: dictionaries only.

Each function emits the shape a real sensor would produce so the analysers can be tested against
behaviour that is known in advance. These are \u201cshapes a defender would see\u201d, not samples of anything.
"""
from __future__ import annotations

import random


def benign_day(seed: int = 7, hosts: int = 4) -> list[dict]:
    """Workstations doing workstation things. The false-positive control."""
    rng = random.Random(seed)
    out: list[dict] = []
    for i in range(hosts):
        host = f"ws-{i:02d}"
        out.append({"kind": "process", "at": 100.0 + i, "host": host, "pid": 1000 + i, "ppid": 1,
                    "image": "excel.exe", "parent": "explorer.exe", "signed": True})
        out.append({"kind": "process", "at": 101.0 + i, "host": host, "pid": 1001 + i, "ppid": 1000 + i,
                    "image": "chrome.exe", "parent": "excel.exe", "signed": True})
        out.append({"kind": "file", "at": 102.0 + i, "host": host, "path": f"C:/Users/a/Documents/q{i}.xlsx",
                    "op": "write", "size": 2048})
        out.append({"kind": "network", "at": 103.0 + i, "host": host, "dst": "updates.vendor.example",
                    "proto": "https", "bytes": 5000})
        for j in range(6):  # a small, ordinary save pattern
            out.append({"kind": "file", "at": 104.0 + j, "host": host,
                        "path": f"C:/Users/a/Documents/notes{j}.docx", "op": "write", "size": 512})
        _ = rng
    return out


def worm_spread(hosts: int = 5) -> list[dict]:
    """One host fanning out over SMB, retrying, and creating a service on each victim."""
    out: list[dict] = []
    for i in range(hosts):
        victim = f"fs-{i:02d}"
        for attempt in range(4):
            out.append({"kind": "network", "at": 200.0 + attempt, "host": "ws-07", "dst": victim,
                        "proto": "smb", "bytes": 900})
        out.append({"kind": "service", "at": 205.0 + i / 10, "host": victim, "name": "WinUpdater",
                    "state": "created"})
        out.append({"kind": "process", "at": 206.0 + i / 10, "host": victim, "pid": 4000 + i, "ppid": 1,
                    "image": "svchost.exe", "parent": "services.exe", "signed": True})
    return out


def trojan_persistence() -> list[dict]:
    """An office document spawning an interpreter and writing an autostart entry."""
    return [
        {"kind": "process", "at": 300.0, "host": "ws-03", "pid": 2200, "ppid": 1,
         "image": "winword.exe", "parent": "explorer.exe", "signed": True},
        {"kind": "process", "at": 301.0, "host": "ws-03", "pid": 2210, "ppid": 2200,
         "image": "powershell.exe", "parent": "winword.exe", "signed": True},
        {"kind": "file", "at": 302.0, "host": "ws-03",
         "path": "C:/Users/a/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/upd.lnk",
         "op": "write", "size": 1200},
        {"kind": "network", "at": 303.0, "host": "ws-03", "dst": "cdn-relay-9.example",
         "proto": "https", "bytes": 40000},
    ]


def ransomware_burst() -> list[dict]:
    """A bulk rewrite, deleted recovery artefacts and egress ahead of impact."""
    out: list[dict] = []
    for i in range(240):
        out.append({"kind": "file", "at": 400.0 + i * 0.2, "host": "fs-01",
                    "path": f"D:/shares/finance/doc{i}.xlsx.locked", "op": "write", "size": 3000})
    out.append({"kind": "file", "at": 500.0, "host": "fs-01", "path": "C:/shadow/copies", "op": "delete"})
    out.append({"kind": "file", "at": 501.0, "host": "fs-01", "path": "D:/shares/.bak/index", "op": "delete"})
    out.append({"kind": "network", "at": 399.0, "host": "fs-01", "dst": "drop-relay-4.example",
                "proto": "https", "bytes": 900_000_000})
    return out
