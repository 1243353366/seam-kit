"""EvidenceGraph: what the observations can actually support.

A person cannot be in Paris at 14:02 and Lyon at 14:05. That much is arithmetic. Everything
else is a judgement about how good the evidence is, and this module refuses to blur the two.

Four grades, and the difference between them is what is missing, not how suspicious it feels:

    confirmed    the conclusion holds even under the most generous reading of the timestamps
    corroborated two independent sources agree and both are intact
    suspected    the arithmetic points one way but the evidence could explain it away
    unknown      the question cannot be answered from what is here

The interesting output is not "this is a fake". It is "these two observations are 392 km apart
and three minutes apart, both chains are intact, and no clock drift could close the gap" versus
"the same two observations, but one identity was never verified, so this is a suspicion".
"""
from __future__ import annotations

import argparse
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone

EARTH_KM = 6371.0088

#: Fastest plausible ground travel between two observations. Rail in France tops out near
#: 320 km/h; anything above this is not a travel plan, it is a contradiction.
DEFAULT_MAX_SPEED_KMH = 320.0

#: The speed limit is a modelling assumption, not a law of physics. A contradiction that sits just
#: above it is a bad assumption, not an impossibility, so the confirmed grade needs margin: only
#: past this multiple is the observation ruled out rather than merely awkward.
IMPOSSIBLE_FACTOR = 1.5

#: Clock drift that a camera is documented to suffer, used when a site does not declare one.
DEFAULT_DRIFT_UNCERTAINTY_S = 5.0


@dataclass(frozen=True)
class Site:
    site_id: str
    lat: float
    lon: float


@dataclass(frozen=True)
class Observation:
    """One thing a sensor claims to have seen, with everything that qualifies it."""

    event_id: str
    site_id: str
    subject: str
    at: datetime
    camera: str = ""
    kind: str = "sighting"
    drift_s: float = 0.0
    drift_uncertainty_s: float | None = None
    identity_verified: bool = True
    custody_ok: bool = True
    source: str = "camera"

    @property
    def corrected(self) -> datetime:
        """Camera clock minus its declared drift. Never silently applied: it is reported."""
        return self.at - _delta(self.drift_s)

    @property
    def uncertainty(self) -> float:
        if self.drift_uncertainty_s is not None:
            return float(self.drift_uncertainty_s)
        return DEFAULT_DRIFT_UNCERTAINTY_S if self.drift_s else 0.0

    def as_evidence(self) -> dict:
        return {
            "event": self.event_id,
            "site": self.site_id,
            "camera": self.camera or None,
            "at": self.at.isoformat(),
            "drift_s": self.drift_s,
            "drift_uncertainty_s": self.uncertainty,
            "identity_verified": self.identity_verified,
            "custody_ok": self.custody_ok,
        }


@dataclass
class Claim:
    claim: str
    grade: str
    reason: str
    evidence: list[dict] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)

    def as_json(self) -> dict:
        return {
            "claim": self.claim,
            "grade": self.grade,
            "reason": self.reason,
            "evidence": self.evidence,
            "missing": self.missing,
        }


def _delta(seconds: float):
    from datetime import timedelta

    return timedelta(seconds=seconds)


def haversine_km(a: Site, b: Site) -> float:
    p1, p2 = math.radians(a.lat), math.radians(b.lat)
    dp = p2 - p1
    dl = math.radians(b.lon - a.lon)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_KM * math.asin(min(1.0, math.sqrt(h)))


def correlate(
    observations: list[Observation],
    sites: dict[str, Site],
    *,
    max_speed_kmh: float = DEFAULT_MAX_SPEED_KMH,
) -> dict:
    """Cross-check independent observations of each subject and grade every conclusion.

    The rule that matters: a contradiction is only confirmed when it survives the most generous
    reading of the clocks. Add the two uncertainties to the gap before computing speed. If it is
    still impossible, drift cannot rescue it, and the claim is confirmed rather than suspected.
    """
    claims: list[Claim] = []
    by_subject: dict[str, list[Observation]] = {}
    for obs in observations:
        by_subject.setdefault(obs.subject, []).append(obs)

    for subject, obs_list in sorted(by_subject.items()):
        ordered = sorted(obs_list, key=lambda o: o.corrected)
        for first, second in zip(ordered, ordered[1:]):
            site_a, site_b = sites.get(first.site_id), sites.get(second.site_id)
            if site_a is None or site_b is None:
                claims.append(
                    Claim(
                        claim=f"{subject}: two observations cannot be compared",
                        grade="unknown",
                        reason=f"site not in the gazetteer: {first.site_id!r} or {second.site_id!r}",
                        evidence=[first.as_evidence(), second.as_evidence()],
                        missing=["site coordinates"],
                    )
                )
                continue

            distance = haversine_km(site_a, site_b)
            gap_s = (second.corrected - first.corrected).total_seconds()
            generous_gap_s = gap_s + first.uncertainty + second.uncertainty

            if distance < 0.2:
                continue  # same building, nothing to say

            if gap_s <= 0 and distance >= 0.2:
                required = math.inf
            elif generous_gap_s <= 0:
                required = math.inf
            else:
                required = distance / (generous_gap_s / 3600.0)

            missing: list[str] = []
            if not (first.identity_verified and second.identity_verified):
                missing.append("identity verified at both sites")
            if not (first.custody_ok and second.custody_ok):
                missing.append("intact custody chain for both exhibits")
            if first.uncertainty == 0.0 or second.uncertainty == 0.0:
                missing.append("declared clock uncertainty for both cameras")

            evidence = [first.as_evidence(), second.as_evidence()]
            travel = (
                f"{distance:.1f} km in {abs(gap_s) / 60.0:.1f} min "
                f"({required:.0f} km/h needed, limit {max_speed_kmh:.0f})"
            )

            if required > max_speed_kmh * IMPOSSIBLE_FACTOR:
                if not missing:
                    claims.append(
                        Claim(
                            claim=f"{subject} cannot have been at both {first.site_id} and {second.site_id}",
                            grade="confirmed",
                            reason=(
                                f"{travel}. Both clocks are documented to within "
                                f"{first.uncertainty:.0f}s and {second.uncertainty:.0f}s, and even with both "
                                f"applied the gap does not close."
                            ),
                            evidence=evidence,
                        )
                    )
                else:
                    claims.append(
                        Claim(
                            claim=f"{subject} may not have been at both {first.site_id} and {second.site_id}",
                            grade="suspected",
                            reason=f"{travel}. The arithmetic is impossible, but the evidence does not close it: "
                            + ", ".join(missing),
                            evidence=evidence,
                            missing=missing,
                        )
                    )
            elif required > max_speed_kmh:
                claims.append(
                    Claim(
                        claim=f"{subject} moved between {first.site_id} and {second.site_id} implausibly fast",
                        grade="suspected",
                        reason=f"{travel}. Possible, not comfortable, and worth a second source.",
                        evidence=evidence,
                        missing=["an independent observation of the journey"],
                    )
                )
            else:
                claims.append(
                    Claim(
                        claim=f"{subject} is consistent between {first.site_id} and {second.site_id}",
                        grade="corroborated" if not missing else "unknown",
                        reason=f"{travel}. Nothing here contradicts a single person travelling.",
                        evidence=evidence,
                        missing=missing,
                    )
                )

    counts: dict[str, int] = {}
    for claim in claims:
        counts[claim.grade] = counts.get(claim.grade, 0) + 1
    return {
        "claims": [c.as_json() for c in claims],
        "summary": counts,
        "max_speed_kmh": max_speed_kmh,
    }


def _parse_time(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def load_case(payload: dict) -> tuple[list[Observation], dict[str, Site]]:
    sites = {
        s["id"]: Site(site_id=s["id"], lat=float(s["lat"]), lon=float(s["lon"]))
        for s in payload.get("sites", [])
    }
    observations = [
        Observation(
            event_id=e.get("id") or f"ev-{i}",
            site_id=e["site"],
            subject=e.get("subject", "unknown"),
            at=_parse_time(e["at"]),
            camera=e.get("camera", ""),
            kind=e.get("kind", "sighting"),
            drift_s=float(e.get("drift_s", 0)),
            drift_uncertainty_s=e.get("drift_uncertainty_s"),
            identity_verified=bool(e.get("identity_verified", True)),
            custody_ok=bool(e.get("custody_ok", True)),
            source=e.get("source", "camera"),
        )
        for i, e in enumerate(payload.get("events", []))
    ]
    return observations, sites


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="grade what a set of observations can support")
    ap.add_argument("case", help="JSON file with sites and events")
    ap.add_argument("--max-speed", type=float, default=DEFAULT_MAX_SPEED_KMH)
    args = ap.parse_args(argv)
    with open(args.case, encoding="utf-8") as fh:
        payload = json.load(fh)
    observations, sites = load_case(payload)
    result = correlate(observations, sites, max_speed_kmh=args.max_speed)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
