"""Metamorphic harness: transform one incident and see whether the conclusion survives.

Two kinds of transformation. *Meaning-preserving* ones change how the same events are written down
(case, whitespace, ordering, clock offset): the report must not change. *Meaning-destroying* ones cut
the evidence apart (different host, different day, unrelated traffic): the grade must fall, because
the relationship that justified it is gone.

Run directly for a table:  python3 -m tools.metamorphic
"""
from __future__ import annotations

import copy
import random

from lab import simulate_incident as sim
from lab import telemetry
from lab import threatlens as lens

EGRESS_BASELINE = 10_000_000


def base_incident() -> list[dict]:
    return copy.deepcopy(sim.ransomware_burst())


def _report(events: list[dict]) -> dict:
    return lens.investigate(events, egress_baseline=EGRESS_BASELINE)


# ---------------------------------------------------------------- meaning-preserving
def recase(events: list[dict]) -> list[dict]:
    out = copy.deepcopy(events)
    for e in out:
        if isinstance(e.get("kind"), str):
            e["kind"] = e["kind"].upper()
        if isinstance(e.get("proto"), str):
            e["proto"] = e["proto"].upper()
        if isinstance(e.get("host"), str):
            e["host"] = f"  {e['host'].upper()}  "
    return out


def offset_clock(events: list[dict]) -> list[dict]:
    out = copy.deepcopy(events)
    for e in out:
        e["at"] = float(e["at"]) + 1_000_000.0
    return out


def shuffle(events: list[dict], seed: int = 0) -> list[dict]:
    out = copy.deepcopy(events)
    random.Random(seed).shuffle(out)
    return out


def straddle(events: list[dict]) -> list[dict]:
    """60 writes split 30/30 across a fixed-one-minute boundary: one rolling burst, two buckets."""
    return [{"kind": "file", "at": 59.9, "host": "fs-01", "path": f"D:/x/a{i}.locked", "op": "write"}
            for i in range(30)] + [
            {"kind": "file", "at": 60.1, "host": "fs-01", "path": f"D:/x/b{i}.locked", "op": "write"}
            for i in range(30)]


# ---------------------------------------------------------------- meaning-destroying
def separate_hosts(events: list[dict]) -> list[dict]:
    """Supporting evidence moved to an unrelated host: the incident is no longer one incident."""
    out = copy.deepcopy(events)
    for e in out:
        if e.get("kind") == "network" or e.get("kind") == "config" \
                or (e.get("kind") == "file" and e.get("op") == "delete"):
            e["host"] = "ws-99"
    return out


def separate_time(events: list[dict], days: int = 3) -> list[dict]:
    out = copy.deepcopy(events)
    for e in out:
        if e.get("kind") in ("config", "network") or (e.get("kind") == "file" and e.get("op") == "delete"):
            e["at"] = float(e["at"]) + days * 86400
    return out


def contaminate(events: list[dict]) -> list[dict]:
    """Unrelated legitimate traffic from other hosts must not lift the original incident."""
    return copy.deepcopy(events) + copy.deepcopy(sim.benign_day())


# ---------------------------------------------------------------- numeric adversaries
def hostile_numbers(events: list[dict]) -> list[dict]:
    out = copy.deepcopy(events)
    out.append({"kind": "network", "at": 1.0, "host": "fs-01", "dst": "x", "proto": "https",
                "bytes": 10 ** 400})
    out.append({"kind": "file", "at": 2.0, "host": "fs-01", "path": "a", "op": "write", "size": -1})
    out.append({"kind": "process", "at": 3.0, "host": "fs-01", "image": "a", "parent": "b",
                "pid": 1.5, "ppid": 1})
    return out


def run() -> list[dict]:
    base = _report(base_incident())
    results: list[dict] = []

    def check(name: str, got: dict, want: str, note: str) -> None:
        if want == "invariant":
            passed = (got["grade"] == base["grade"]
                      and [f["observed"] for f in got["findings"]] == [f["observed"] for f in base["findings"]])
        elif want == "drop":
            passed = got["grade"] != "corroborated"
        elif want == "detect":
            passed = got["grade"] != "unknown"
        elif want == "refuse":
            passed = got["events_rejected"] >= 3
        else:
            passed = False
        results.append({"case": name, "expects": want, "passed": passed, "grade": got["grade"],
                        "baseline": base["grade"], "note": note})

    check("recase", _report(recase(base_incident())), "invariant", "case and whitespace only")
    check("offset_clock", _report(offset_clock(base_incident())), "invariant", "+11.6 days for every event")
    check("shuffle", _report(shuffle(base_incident(), seed=3)), "invariant", "same events, new order")
    check("straddle", _report(straddle([])), "detect", "60 writes across a one-minute boundary")
    check("separate_hosts", _report(separate_hosts(base_incident())), "drop", "supporting events moved host")
    check("separate_time", _report(separate_time(base_incident())), "drop", "supporting events moved 3 days")
    check("contaminate", _report(contaminate(base_incident())), "invariant", "unrelated benign traffic added")
    check("hostile_numbers", _report(hostile_numbers(base_incident())), "refuse", "huge, negative, fractional")
    return results


def table(results: list[dict]) -> str:
    lines = ["| case | expects | grade | baseline | ok |", "| --- | --- | --- | --- | --- |"]
    for r in results:
        lines.append(f"| {r['case']} | {r['expects']} | {r['grade']} | {r['baseline']} | "
                     f"{'pass' if r['passed'] else 'FAIL'} |")
    return "\n".join(lines)


if __name__ == "__main__":
    rows = run()
    print(table(rows))
    raise SystemExit(0 if all(r["passed"] for r in rows) else 1)
