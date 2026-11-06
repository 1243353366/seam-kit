"""One event schema, because four engines otherwise invent four representations of an event."""
from __future__ import annotations

import math

KINDS = {"process", "file", "network", "service", "auth", "privilege", "config"}

#: Per-kind requirements. `at` and `host` are universal; everything else is kind-specific.
REQUIRED: dict[str, tuple[str, ...]] = {
    "process": ("image", "parent", "pid", "ppid"),
    "file": ("path", "op"),
    "network": ("dst", "proto"),
    "service": ("name", "state"),
    "auth": ("user", "result"),
    "privilege": ("user", "elevated"),
    "config": ("key", "op"),
}

FILE_OPS = {"write", "delete", "rename", "create", "modify"}
CONFIG_OPS = {"create", "modify", "delete", "disable"}


class SchemaError(ValueError):
    """Raised when an event cannot be read as telemetry. Never silently converted."""


def normalise(event: dict) -> dict:
    """Lower-case hosts and images, coerce `at` to float. Field values only: nothing is inferred."""
    out = dict(event)
    out["kind"] = str(event.get("kind", "")).lower()
    if isinstance(event.get("host"), str):
        out["host"] = event["host"].strip().lower()
    for key in ("image", "parent", "proto", "op", "result", "path", "dst", "key"):
        if isinstance(event.get(key), str):
            out[key] = event[key].strip()
    try:
        out["at"] = float(event.get("at"))
    except (TypeError, ValueError):
        pass
    return out


def problems(events: list[dict]) -> list[str]:
    """Every reason a stream cannot be trusted, rather than the first one found."""
    found: list[str] = []
    for i, event in enumerate(events):
        where = f"event {i}"
        if not isinstance(event, dict):
            found.append(f"{where}: not an object")
            continue
        if event.get("kind") not in KINDS:
            found.append(f"{where}: unknown kind {event.get('kind')!r}")
            continue
        at = event.get("at")
        if not isinstance(at, (int, float)) or isinstance(at, bool) or not math.isfinite(float(at)):
            found.append(f"{where}: `at` is not a finite timestamp")
        for field in ("bytes", "pid", "ppid", "size"):
            if field not in event or event[field] is None:
                continue
            value = event[field]
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(float(value)):
                found.append(f"{where}: `{field}` is not a finite number")
        if not isinstance(event.get("host"), str) or not event["host"].strip():
            found.append(f"{where}: no host")
        for field in REQUIRED.get(event["kind"], ()):
            if event.get(field) in (None, ""):
                found.append(f"{where} ({event['kind']}): missing {field}")
        if event["kind"] == "file" and event.get("op") not in FILE_OPS:
            found.append(f"{where} (file): op {event.get('op')!r} is not one of {sorted(FILE_OPS)}")
        if event["kind"] == "config" and event.get("op") not in CONFIG_OPS:
            found.append(f"{where} (config): op {event.get('op')!r} is not one of {sorted(CONFIG_OPS)}")
        if event["kind"] == "privilege" and not isinstance(event.get("elevated"), bool):
            found.append(f"{where} (privilege): `elevated` must be true or false, not a guess")
    return found


def check(events: list[dict]) -> list[dict]:
    """Validate and normalise, or raise. An engine that reads malformed telemetry grades noise."""
    found = problems(events)
    if found:
        raise SchemaError("; ".join(found[:6]) + (f" (+{len(found) - 6} more)" if len(found) > 6 else ""))
    return [normalise(e) for e in events]


def extension(path: str) -> str:
    """Last dotted segment, lower-cased. `report.xlsx.locked` is `.locked`, which is the point."""
    tail = str(path).replace("\\", "/").rsplit("/", 1)[-1]
    return ("." + tail.rsplit(".", 1)[1].lower()) if "." in tail else ""


def by_host(events: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for event in events:
        out.setdefault(event["host"], []).append(event)
    return out
