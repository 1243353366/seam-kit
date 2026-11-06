"""One event schema, because four engines otherwise invent four representations of an event.

Canonicalisation happens *before* validation: `{"kind": "PROCESS"}` is the same event as
`{"kind": "process"}`, and a schema that rejects one and accepts the other is measuring typing, not
telemetry.
"""
from __future__ import annotations

import math

KINDS = {"process", "file", "network", "service", "auth", "privilege", "config"}

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

#: Counters and sizes. Negative values are refused rather than read as small positives.
COUNTERS = ("bytes", "size")
#: Identifiers. Fractional identifiers are a sensor bug, not a measurement.
IDENTIFIERS = ("pid", "ppid")


class SchemaError(ValueError):
    """Raised when an event cannot be read as telemetry. Never silently converted."""


def normalise(event: dict) -> dict:
    """Canonical form: lower-case vocabulary, stripped strings, numeric timestamps."""
    out = dict(event)
    for key in ("kind", "proto", "op", "result", "state", "key", "dst", "user"):
        if isinstance(out.get(key), str):
            out[key] = out[key].strip().lower()
    for key in ("host", "image", "parent", "name", "path"):
        if isinstance(out.get(key), str):
            out[key] = out[key].strip()
    if isinstance(out.get("host"), str):
        out["host"] = out["host"].lower()
    try:
        out["at"] = float(event.get("at"))
    except (TypeError, ValueError, OverflowError):
        pass
    return out


def _finite(value) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(float(value))  # a huge int can raise on conversion
    except (OverflowError, ValueError):
        return False


def problems(events: list[dict]) -> list[str]:
    """Every reason a stream cannot be trusted, after canonicalisation and before arithmetic."""
    found: list[str] = []
    for i, raw in enumerate(events):
        where = f"event {i}"
        if not isinstance(raw, dict):
            found.append(f"{where}: not an object")
            continue
        event = normalise(raw)
        if event.get("kind") not in KINDS:
            found.append(f"{where}: unknown kind {raw.get('kind')!r}")
            continue
        if not _finite(event.get("at")):
            found.append(f"{where}: `at` is not a finite timestamp")
        if not isinstance(event.get("host"), str) or not event["host"]:
            found.append(f"{where}: no host")
        for field in REQUIRED.get(event["kind"], ()):
            if event.get(field) in (None, ""):
                found.append(f"{where} ({event['kind']}): missing {field}")
        if event["kind"] == "file" and event.get("op") not in FILE_OPS:
            found.append(f"{where} (file): op {raw.get('op')!r} is not one of {sorted(FILE_OPS)}")
        if event["kind"] == "config" and event.get("op") not in CONFIG_OPS:
            found.append(f"{where} (config): op {raw.get('op')!r} is not one of {sorted(CONFIG_OPS)}")
        if event["kind"] == "privilege" and not isinstance(event.get("elevated"), bool):
            found.append(f"{where} (privilege): `elevated` must be true or false, not a guess")
        for field in COUNTERS:
            if event.get(field) is None:
                continue
            if not _finite(event[field]) or event[field] < 0:
                found.append(f"{where}: `{field}` must be a finite non-negative number")
        for field in IDENTIFIERS:
            if event.get(field) is None:
                continue
            value = event[field]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                found.append(f"{where}: `{field}` must be a non-negative integer")
    return found


def check(events: list[dict]) -> list[dict]:
    """Validate and return canonical events, or raise. An engine that reads malformed telemetry
    grades noise."""
    found = problems(events)
    if found:
        raise SchemaError("; ".join(found[:6]) + (f" (+{len(found) - 6} more)" if len(found) > 6 else ""))
    return [normalise(e) for e in events]


def order_key(event: dict) -> tuple:
    """Deterministic ordering. The examiner's evidence must not depend on arrival order."""
    return (event.get("at", 0.0), event.get("host", ""), event.get("kind", ""),
            str(event.get("path") or event.get("dst") or event.get("image") or event.get("key") or ""))


def sorted_events(events: list[dict]) -> list[dict]:
    return sorted((normalise(e) for e in events if isinstance(e, dict)), key=order_key)


def extension(path: str) -> str:
    tail = str(path).replace("\\", "/").rsplit("/", 1)[-1]
    return ("." + tail.rsplit(".", 1)[1].lower()) if "." in tail else ""


def by_host(events: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for event in events:
        out.setdefault(event["host"], []).append(event)
    return out
