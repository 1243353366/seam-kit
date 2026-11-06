"""Counter-forensics: what a concealment attempt cannot remove.

The question is not "was this edited" but "what should still exist if someone tried to hide it".
A concealment leaves its own shape: a file whose clock disagrees with the record of when its
content existed, metadata the pipeline wrote and the copy no longer carries, a container that
announces it was written by an encoder rather than a camera.

Four checks, each returning a finding with a reason and the limitation that stops it from being
more than it is:

  clock      the file's modification time against the sealed record of its content
  provenance metadata the pipeline recorded that the file no longer carries
  container  re-encode markers: missing creation time, encoder tag, frame-count disagreement
  record     rows missing from a sealed manifest (delegated to guard.verify)

None of these detects editing. All of them detect *having tried to hide* editing, which is a
different claim and a much cheaper one to defend.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

#: How much clock difference is ordinary filesystem sloppiness rather than a finding.
CLOCK_TOLERANCE_S = 120.0

PROVENANCE_KEYS = ("creation_time", "encoder", "comment")


@dataclass
class ConcealmentFinding:
    check: str
    finding: str
    detail: str
    limitation: str
    severity: str = "S3"
    # Observed alteration is a fact about the file. Inconsistency is a disagreement with a record
    # kept elsewhere. Concealment is a reading of intent, and intent is the weakest of the three.
    category: str = "observed_alteration"

    def as_dict(self) -> dict:
        return {
            "check": self.check,
            "finding": self.finding,
            "detail": self.detail,
            "limitation": self.limitation,
            "severity": self.severity,
            "category": self.category,
        }


def probe(path: str) -> dict:
    """Container and stream facts through ffprobe. Empty dict when ffprobe is unavailable."""
    if shutil.which("ffprobe") is None:
        return {"unavailable": "ffprobe not found"}
    out = subprocess.run(
        ["ffprobe", "-v", "error", "-print_format", "json", "-show_format", "-show_streams", str(path)],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        return {"unavailable": out.stderr.strip()[:200]}
    data = json.loads(out.stdout or "{}")
    fmt = data.get("format", {})
    streams = data.get("streams", [])
    video = next((s for s in streams if s.get("codec_type") == "video"), {})
    return {
        "format_name": fmt.get("format_name"),
        "size_bytes": int(fmt.get("size", 0) or 0),
        "tags": {k.lower(): v for k, v in (fmt.get("tags") or {}).items()},
        "codec": video.get("codec_name"),
        "frames": int(video.get("nb_frames", 0) or 0),
        "duration": float(fmt.get("duration", 0.0) or 0.0),
    }


def clock(path: str) -> dict:
    st = os.stat(path)
    return {"mtime": st.st_mtime, "ctime": st.st_ctime, "size": st.st_size}


def check_clock(sealed_at: float, mtime: float, *, content_changed: bool | None = None,
                tolerance: float = CLOCK_TOLERANCE_S) -> list[ConcealmentFinding]:
    """Compare the file's clock with the record of when its content existed.

    Direction matters and my first version had it backwards. Sealing happens *after* writing, so
    an mtime earlier than the seal is the normal shape of an honest file. The two shapes worth
    reporting are a file that changed after it was sealed, and one that claims to predate the seal
    while no longer being the sealed content.
    """
    if mtime > sealed_at + tolerance:
        return [
            ConcealmentFinding(
                "clock",
                "file changed after its content was recorded",
                f"mtime is {mtime - sealed_at:.0f}s later than the sealed record",
                "a legitimate re-encode or metadata write moves this too",
                "S2",
            )
        ]
    if content_changed and mtime < sealed_at - tolerance:
        return [
            ConcealmentFinding(
                "clock",
                "clock set back on a file that is not the sealed content",
                f"mtime is {sealed_at - mtime:.0f}s earlier than the seal, and the digest differs",
                "a restore from backup of a different version produces the same shape",
                "S2",
                "inconsistent_with_record",
            )
        ]
    return []


def check_provenance(tags: dict, expected: tuple[str, ...] = PROVENANCE_KEYS) -> list[ConcealmentFinding]:
    """Metadata the pipeline wrote that the copy no longer carries."""
    missing = [k for k in expected if k not in tags]
    if not missing:
        return []
    return [
        ConcealmentFinding(
            "provenance",
            "recorded metadata absent from the copy",
            "missing: " + ", ".join(missing),
            "stripping is routine in privacy tooling and some platforms; absence is not intent",
            "S3",
            "possible_concealment",
        )
    ]


def check_container(facts: dict, expected_frames: int | None = None) -> list[ConcealmentFinding]:
    """Markers that say a tool wrote this file, not a camera."""
    out: list[ConcealmentFinding] = []
    tags = facts.get("tags") or {}
    if facts.get("unavailable"):
        return out
    if "creation_time" not in tags:
        out.append(
            ConcealmentFinding(
                "container",
                "no creation time in the container",
                f"format {facts.get('format_name')} carries no creation_time",
                "many cameras never write one, so this alone proves nothing",
                "S3",
                "possible_concealment",
            )
        )
    encoder = str(tags.get("encoder", "")).lower()
    if any(k in encoder for k in ("lavf", "libx264", "ffmpeg", "handbrake")):
        out.append(
            ConcealmentFinding(
                "container",
                "written by an encoder rather than a camera",
                f"encoder tag: {tags.get('encoder')}",
                "any re-encode for distribution leaves this, including innocent ones",
            )
        )
    if expected_frames is not None and facts.get("frames") and facts["frames"] != expected_frames:
        out.append(
            ConcealmentFinding(
                "container",
                "frame count disagrees with the sealed record",
                f"{facts['frames']} present, {expected_frames} recorded",
                "container frame counts are often estimated, so this needs the decoded count",
                "S2",
                "inconsistent_with_record",
            )
        )
    return out


def report(path: str, *, sealed_at: float | None = None, content_changed: bool | None = None,
           expected_frames: int | None = None,
           expected_tags: tuple[str, ...] = PROVENANCE_KEYS) -> dict:
    facts = probe(path)
    findings: list[ConcealmentFinding] = []
    stamp = clock(path)
    if sealed_at is not None:
        findings += check_clock(sealed_at, stamp["mtime"], content_changed=content_changed)
    findings += check_provenance(facts.get("tags", {}), expected_tags)
    findings += check_container(facts, expected_frames)
    return {
        "path": str(path),
        "clock": stamp,
        "container": facts,
        "findings": [f.as_dict() for f in findings],
        "clean": not findings,
        "limits": [
            "concealment is not manipulation: every finding here has an innocent twin",
            "a file that was never sealed cannot be checked against a record",
            "nothing here examines the pixels; that is the other modules' business",
        ],
    }
