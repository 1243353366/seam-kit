"""Corpus intake: quarantine with a reason attached, and a manifest you can check later.

Two design choices worth stating, because they are where this differs from a poisoning tool:

1. Suspect rows are quarantined, never deleted and never altered. A row you cannot inspect is a
   row you cannot defend, and "the filter ate it" is not an answer you can give anyone.
2. Published rows carry a canary tag derived from the key, so if the corpus later turns up in a
   model that should not have it, the tag is evidence. The rows themselves stay true. A corpus
   seeded with false labels cannot prove anything: whoever ingests it can point at your lies
   instead of your rights.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
from collections import Counter, defaultdict

BANDS, ROWS_PER_BAND, SHINGLE = 8, 8, 3
SEED_MIN_SIM = 0.35

#: One record is expected to be small. A line beyond this is refused rather than parsed:
#: a gigabyte of JSON is either a mangled export or a test of your parser's memory ceiling.
MAX_LINE_CHARS = 1 << 20


def canon(rec: dict) -> bytes:
    return json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9_]+", text.lower())


def text_of(rec: dict) -> str:
    return " ".join(str(rec.get(k, "")) for k in ("title", "text", "body"))


def shingles(text: str) -> list[str]:
    toks = tokens(text)
    if len(toks) < SHINGLE:
        return [" ".join(toks)] if toks else []
    return [" ".join(toks[i : i + SHINGLE]) for i in range(len(toks) - SHINGLE + 1)]


def signature(text: str) -> tuple[int, ...]:
    grams = shingles(text)
    if not grams:
        return (0,) * (BANDS * ROWS_PER_BAND)
    hashes = {int.from_bytes(hashlib.blake2b(g.encode(), digest_size=8).digest(), "big") for g in grams}
    out = []
    for i in range(BANDS * ROWS_PER_BAND):
        salt = (i + 1) * 0x9E3779B97F4A7C15
        out.append(min(((h ^ salt) * 0x27220A95) & 0xFFFFFFFFFFFFFFFF for h in hashes))
    return tuple(out)


def bands(sig: tuple[int, ...]) -> list[tuple[int, int]]:
    return [(i, hash(sig[i * ROWS_PER_BAND : (i + 1) * ROWS_PER_BAND])) for i in range(BANDS)]


def key() -> bytes:
    value = os.environ.get("SEAM_KEY", "").strip()
    if len(value) < 16:
        raise SystemExit("set SEAM_KEY to a long random string (>= 16 chars); there is no default")
    return value.encode()


def sign(payload: dict, material: bytes) -> str:
    return hmac.new(material, json.dumps(payload, sort_keys=True).encode(), hashlib.sha256).hexdigest()


def canary(rid: str, material: bytes) -> str:
    return "sc-" + hmac.new(material, f"canary:{rid}".encode(), hashlib.sha256).hexdigest()[:12]


def _cosine(a: Counter, b: Counter) -> float:
    common = set(a) & set(b)
    dot = sum(a[k] * b[k] for k in common)
    na = sum(v * v for v in a.values()) ** 0.5
    nb = sum(v * v for v in b.values()) ** 0.5
    return dot / (na * nb) if na and nb else 0.0


def _load_seed(path: str | None) -> list[Counter]:
    if not path:
        return []
    with open(path, encoding="utf-8") as fh:
        rows = [Counter(tokens(text_of(json.loads(line)))) for line in fh if line.strip()]
    if len(rows) < 3:
        raise SystemExit(f"{path}: a seed set of {len(rows)} rows cannot calibrate anything; want >= 3")
    return rows


def ingest(incoming: str, clean_path: str, quarantine_path: str, manifest_path: str,
           seed_path: str | None = None, material: bytes | None = None) -> dict:
    material = material or key()  # noqa: F841 - proves the key exists before any work starts
    seed = _load_seed(seed_path)
    records: dict[str, dict] = {}
    buckets: dict[tuple[int, int], list[str]] = defaultdict(list)

    with open(incoming, encoding="utf-8") as fh:
        lines = [line.strip() for line in fh if line.strip()]

    too_long = 0
    for line in lines:
        if not line:
            continue
        # A single record is a few kilobytes. A line that big is either a mangled export or
        # someone handing you a gigabyte to see what your parser does with it.
        if len(line) > MAX_LINE_CHARS:
            too_long += 1
            continue
        rec = json.loads(line)
        rid = sha256_hex(canon(rec))[:16]
        if rid in records:
            continue
        rec["_id"] = rid
        records[rid] = rec
        for band in bands(signature(text_of(rec))):
            buckets[band].append(rid)

    status = {rid: ("clean", "") for rid in records}
    clusters = [set(v) for v in buckets.values() if len(v) > 1]

    # A near-duplicate cluster that disagrees with itself is the cheapest poisoning signal there
    # is. It is also the one that fails against a flood bigger than your honest copies, which is
    # why cluster sizes are reported rather than quietly trusted.
    for group in clusters:
        labels = Counter(records[r]["label"] for r in group)
        if len(labels) == 1:
            continue
        majority, count = labels.most_common(1)[0]
        for rid in group:
            if records[rid]["label"] != majority:
                status[rid] = ("suspect", f"label disagrees with {count} of {len(group)} near-duplicates")

    if seed:
        for rid, rec in records.items():
            vec = Counter(tokens(text_of(rec)))
            best = max((_cosine(vec, s) for s in seed), default=0.0)
            if best < SEED_MIN_SIM:
                status[rid] = ("suspect", f"outside the seed set (best cosine {best:.2f})")

    entries = []
    with open(clean_path, "w", encoding="utf-8") as clean, open(quarantine_path, "w", encoding="utf-8") as quar:
        for rid in sorted(records):
            rec = dict(records[rid])
            state, reason = status[rid]
            rec["_status"], rec["_reason"] = state, reason
            rec["_canary"] = canary(rid, material)
            handle = quar if state == "suspect" else clean
            handle.write(json.dumps(rec, sort_keys=True) + "\n")
            entries.append({
                "id": rid,
                "sha256": sha256_hex(canon(records[rid])),
                "status": state,
                "reason": reason,
                "canary": rec["_canary"],
            })

    write_manifest(manifest_path, entries, material)

    quarantined = sum(1 for s, _ in status.values() if s == "suspect")
    return {
        "rows": len(records),
        "oversized_lines": too_long,
        "clean": len(records) - quarantined,
        "quarantined": quarantined,
        "clusters": len(clusters),
        "largest_cluster": max((len(c) for c in clusters), default=0),
        "manifest": manifest_path,
    }


def write_manifest(manifest_path: str, entries: list[dict], material: bytes | None = None) -> dict:
    """Sign each row, then seal the row count and the last signature.

    A per-row HMAC proves a row was not edited. It says nothing about a row that was deleted,
    because a shorter manifest verifies exactly as well as a longer one. The seal is what makes a
    missing line a failure instead of a tidy file, and it is written here rather than inside
    `ingest` so any record can be sealed without pretending to be corpus rows.
    """
    material = material or key()
    signed = []
    for entry in entries:
        body = {k: v for k, v in entry.items() if k != "sig"}
        row = dict(body)
        row["sig"] = sign(body, material)
        signed.append(row)

    seal = {"__seal__": True, "count": len(signed), "head": signed[-1]["sig"] if signed else ""}
    seal["sig"] = sign({"__seal__": True, "count": seal["count"], "head": seal["head"]}, material)
    with open(manifest_path, "w", encoding="utf-8") as fh:
        for row in signed:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
        fh.write(json.dumps(seal, sort_keys=True) + "\n")
    return {"count": len(signed), "head": seal["head"]}


def verify(manifest_path: str, material: bytes | None = None) -> tuple[bool, int, int]:
    """Check every row's signature and the seal over all of them.

    Returns (ok, rows, problems). ``problems`` counts refusals, not rows: an oversized line, a
    missing seal, a count that disagrees with the seal and a rewritten last row each add one.
    """
    material = material or key()
    with open(manifest_path, encoding="utf-8") as fh:
        lines = [line.strip() for line in fh if line.strip()]

    oversized = sum(1 for line in lines if len(line) > MAX_LINE_CHARS)
    lines = [line for line in lines if len(line) <= MAX_LINE_CHARS]

    bad = 0
    parsed: list[dict] = []
    for line in lines:
        entry = json.loads(line)
        claimed = entry.get("sig", "")
        body = {k: v for k, v in entry.items() if k != "sig"}
        if not hmac.compare_digest(claimed, sign(body, material)):
            bad += 1
        parsed.append(entry)

    seals = [e for e in parsed if e.get("__seal__")]
    rows = [e for e in parsed if not e.get("__seal__")]

    problems = bad + oversized
    if len(seals) != 1:
        problems += 1  # no seal, or more than one, and neither is a manifest we wrote
    else:
        if seals[0].get("count") != len(rows):
            problems += 1
        if rows and seals[0].get("head") != rows[-1].get("sig"):
            problems += 1
    return problems == 0, len(rows), problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guard")
    sub = parser.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("ingest")
    i.add_argument("--in", dest="incoming", required=True)
    i.add_argument("--clean", required=True)
    i.add_argument("--quarantine", required=True)
    i.add_argument("--manifest", required=True)
    i.add_argument("--seed")

    v = sub.add_parser("verify")
    v.add_argument("--manifest", required=True)

    args = parser.parse_args(argv)

    if args.cmd == "ingest":
        print(json.dumps(ingest(args.incoming, args.clean, args.quarantine, args.manifest, args.seed), indent=2))
        return 0

    ok, total, bad = verify(args.manifest)
    print(f"{'OK' if ok else 'TAMPERED'} {total - bad}/{total} entries verified")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
