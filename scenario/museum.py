"""The museum case: one investigation, start to finish.

The show gives the scenario and not the method, so this is the method applied to a synthetic case
built to have the same shape:

  a camera feed showing a man at a museum at 14:07
  a custody record with him in a cell at 14:00, independent of the footage
  a camera manifest whose rows changed after it was sealed
  a file whose clock was set back and whose provenance was stripped
  an operator whose credential authenticated and whose permission did not cover the write

Nothing here is real footage and nothing here is a real person. Every report says so.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import numpy as np

from lab import adjudicate, conceal, guard_bridge, identity, synth, temporal

CASE = "museum-surveillance"
SIGHTING_AT = "2026-11-05T14:07:00Z"
CUSTODY_AT = "2026-11-05T14:00:00Z"


def _write_feed(tmp: Path, *, doctored: bool) -> str:
    if doctored:
        # The donor drifts, which is what a sequence-level fake looks like when the generator
        # cannot hold a head steady. It is also what makes the temporal signals worth having.
        frames = np.stack(
            [
                np.roll(synth.manipulate(synth.face_frame(seed=i, size=128), seed=700 + i), i * 2, axis=1)
                for i in range(10)
            ]
        )
    else:
        frames = np.stack([synth.face_frame(seed=i, size=128) for i in range(10)])
    path = str(tmp / ("cam2-doctored.mp4" if doctored else "cam2-original.mp4"))
    temporal.write_video(frames, path, fps=6)
    return path


def _tag(path: str, tmp: Path) -> str:
    tagged = str(tmp / "cam2-tagged.mp4")
    subprocess.run(
        ["ffmpeg", "-v", "error", "-y", "-i", path, "-c", "copy",
         "-metadata", "creation_time=2026-11-05T14:07:00Z",
         "-metadata", "comment=sealed-by-camera-2",
         tagged],
        check=True,
    )
    return tagged


def _strip_and_backdate(tagged: str, tmp: Path, sealed_at: float) -> str:
    hidden = str(tmp / "cam2-injected.mp4")
    subprocess.run(
        ["ffmpeg", "-v", "error", "-y", "-i", tagged, "-map_metadata", "-1",
         "-c:v", "libx264", hidden],
        check=True,
    )
    os.utime(hidden, (sealed_at - 86400, sealed_at - 86400))
    return hidden


def _camera_manifest(tmp: Path) -> tuple[str, bool, int]:
    """A sealed record of the camera's rows, then one row removed. The seal is what notices."""
    ledger = str(tmp / "camera-log.jsonl")
    manifest = str(tmp / "camera-manifest.jsonl")
    rows = [{"camera": "CAM-2", "event": f"clip-{i}", "note": "routine write"} for i in range(4)]
    Path(ledger).write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    guard_bridge.write_manifest(manifest, rows)
    ok_before, rows_before, _ = guard_bridge.verify(manifest)

    lines = [line for line in Path(manifest).read_text(encoding="utf-8").splitlines() if line.strip()]
    Path(manifest).write_text("\n".join(lines[:-2] + lines[-1:]) + "\n", encoding="utf-8")
    ok_after, rows_after, problems = guard_bridge.verify(manifest)
    return manifest, (ok_before and not ok_after), rows_before - rows_after


def investigate(tmp_dir: str | None = None) -> dict:
    with tempfile.TemporaryDirectory() if tmp_dir is None else _nullcontext(tmp_dir) as raw:
        tmp = Path(raw)
        authentic = _write_feed(tmp, doctored=False)
        doctored = _write_feed(tmp, doctored=True)
        tagged = _tag(doctored, tmp)
        sealed_at = os.stat(tagged).st_mtime + 300.0
        injected = _strip_and_backdate(tagged, tmp, sealed_at)

        frames = temporal.load_video(injected, size=128) if shutil.which("ffmpeg") else None
        temporal_signals = temporal.analyse(frames) if frames is not None else {"unavailable": True}

        signal_block = {
            "temporal_drift": {"verdict": "suspect" if temporal_signals.get("drift", 0) > 0.2 else "clean"},
            "temporal_flicker": {"verdict": "suspect" if temporal_signals.get("flicker", 0) > 0.10 else "clean"},
            "temporal_cut": {"verdict": "suspect" if temporal_signals.get("cut", 0) > 6.0 else "clean"},
        }
        concealment = conceal.report(
            injected, sealed_at=sealed_at, content_changed=True,
            expected_tags=("creation_time", "comment"),
        )
        manifest, tampered, lost_rows = _camera_manifest(tmp)

        cred = identity.issue("adele", "restorer", b"case-secret-for-the-museum-drill")
        access = identity.attempt(cred, "camera:write", b"case-secret-for-the-museum-drill")

        provenance = {"chain_intact": not tampered, "insertion_evidence": False}
        media = adjudicate.media_claim(signal_block, provenance=provenance)
        custody = [{"independent": True, "source": "facility custody log", "at": CUSTODY_AT}]
        event = adjudicate.event_claim(media, custody)
        event_without = adjudicate.event_claim(media)

        claims = [
            {"id": "media", **media},
            {"id": "event", **event},
            {
                "id": "record",
                "claim": "record_tampered",
                "grade": "confirmed" if tampered else "unknown",
                "basis": [f"sealed manifest lost {lost_rows} row(s) and stopped verifying"],
                "limitations": [
                    "the seal proves rows changed, not who changed them",
                    "the writing identity is a separate claim, made below",
                ],
            },
            {
                "id": "concealment",
                "claim": "concealment_attempt",
                "grade": "corroborated" if len(concealment["findings"]) >= 2 else "suspected",
                "basis": [f"{f['check']}: {f['finding']}" for f in concealment["findings"]],
                "limitations": [f["limitation"] for f in concealment["findings"]]
                + ["every finding here has an innocent twin; intent is not established"],
            },
            {
                "id": "access",
                "claim": "operator_wrote_to_camera",
                "grade": "unknown",
                "basis": [],
                "authenticated": access.authenticated,
                "authorized": access.authorized,
                "reason": access.reason,
                "limitations": [
                    "authentication says who, not who did it",
                    "the credential is a model of a real one, not the real one",
                ],
            },
        ]

        return {
            "case": CASE,
            "synthetic": True,
            "sighting_at": SIGHTING_AT,
            "custody_at": CUSTODY_AT,
            "claims": claims,
            "evidence": {
                "authentic": os.path.basename(authentic),
                "injected": os.path.basename(injected),
                "manifest": os.path.basename(manifest),
                "temporal": temporal_signals,
                "concealment": concealment["findings"],
                "rows_lost": lost_rows,
                "event_without_corroboration": event_without["grade"],
            },
            "limits": [
                "the footage is generated by this repository's synthesiser, so detection here is a "
                "statement about the method, not about footage from the world",
                "the custody log is an input, and an input can be wrong",
                "no audio, no multiple cameras, no telemetry",
            ],
        }


class _nullcontext:
    """Kept tiny on purpose: a directory that already exists is not ours to delete."""

    def __init__(self, value: str):
        self.value = value

    def __enter__(self) -> str:
        Path(self.value).mkdir(parents=True, exist_ok=True)
        return self.value

    def __exit__(self, *exc) -> bool:
        return False


def to_markdown(report: dict) -> str:
    lines = [f"# Case {report['case']}", "", "Synthetic case. Generated footage, modelled identities.", ""]
    lines.append("| claim | grade | basis |")
    lines.append("| --- | --- | --- |")
    for claim in report["claims"]:
        basis = "; ".join(claim.get("basis") or []) or claim.get("reason", "")
        lines.append(f"| {claim['id']} | **{claim['grade']}** | {basis} |")
    lines.append("")
    lines.append("## What the evidence cannot carry")
    for claim in report["claims"]:
        for limit in claim.get("limitations", []):
            lines.append(f"- ({claim['id']}) {limit}")
    lines.append("")
    lines.append("## What this run cannot establish")
    for limit in report["limits"]:
        lines.append(f"- {limit}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    out = Path(argv[0]) if argv else Path("case-report")
    out.mkdir(parents=True, exist_ok=True)
    report = investigate()
    (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (out / "report.md").write_text(to_markdown(report), encoding="utf-8")
    print(to_markdown(report))
    return 0


if __name__ == "__main__":  # pragma: no cover
    import sys

    raise SystemExit(main(sys.argv[1:]))
