"""The adjudicator: what the evidence supports, what it does not, and why.

Two claims look alike and are not:

  media_synthetic   the pixels were produced or altered by a generative process
  event_false       the recorded event did not happen

Media evidence can support the first. It cannot support the second: a fabricated clip and a real
event later altered look the same from inside the frame. That is a ceiling in the code rather than
advice in a document, so a test can fail if someone removes it.
"""
from __future__ import annotations

import math

from . import synth
from .signals import all_signals, oriented

GRADES = ("confirmed", "corroborated", "suspected", "unknown")

#: Media signals that must agree before a grade is allowed past "suspected". This is a stopgap and
#: it is labelled as one: signals measured on the same pixels are not established to be independent,
#: so counting them is not evidence fusion. A grade above "suspected" also requires measured
#: operating points; uncalibrated defaults cannot carry it.
AGREEMENT_FOR_CORROBORATED = 2


def _limitations(signals: dict, provenance: dict | None, calibration: dict | None) -> list[str]:
    out: list[str] = []
    if calibration is None:
        out.append("thresholds are uncalibrated defaults, not measured operating points")
    verdicts = [s.get("verdict") for s in signals.values()]
    if "suspect" in verdicts and "clean" in verdicts:
        out.append("signals disagree, so no single reading is decisive")
    if not provenance:
        out.append("no provenance: nothing establishes how the file was produced or handled")
    elif not provenance.get("chain_intact", False):
        out.append("custody chain broken, so this may not be the file that was examined")
    return out


def media_claim(
    signals: dict, provenance: dict | None = None, calibration: dict | None = None
) -> dict:
    """Grade the claim "these pixels are synthetic" from whatever the signals can support."""
    agree = sorted(n for n, s in signals.items() if s.get("verdict") == "suspect")
    clean = sorted(n for n, s in signals.items() if s.get("verdict") == "clean")
    # Provenance only counts while its chain verifies. A broken chain is a chain you cannot
    # read, and reading it anyway is how a fabrication gets marked confirmed.
    # Provenance still cannot carry a grade. `insertion_evidence` is a field someone asserted; this
    # layer cannot check it, and a claim it cannot check must not promote anything. It is reported
    # as a basis item and nothing more.
    insertion = bool(
        provenance and provenance.get("insertion_evidence") and provenance.get("chain_intact")
    )
    calibrated = bool(calibration and calibration.get("operating_points"))

    if len(agree) >= AGREEMENT_FOR_CORROBORATED:
        grade = "corroborated"
    elif agree:
        grade = "suspected"
    else:
        grade = "unknown"

    if grade == "corroborated" and not calibrated:
        # Thresholds measured on nothing are a guess with a decimal point.
        grade = "suspected"

    basis = list(agree)
    if insertion:
        basis.append("provenance: an insertion point is asserted in the custody record, unverified here")
    limitations = _limitations(signals, provenance, calibration)
    if grade == "suspected" and len(agree) >= AGREEMENT_FOR_CORROBORATED:
        limitations.append("agreement was capped by missing calibration")

    return {
        "claim": "media_synthetic",
        "grade": grade,
        "signals_agreeing": agree,
        "signals_clean": clean,
        "calibrated": calibrated,
        "basis": basis,
        "limitations": limitations,
    }


def calibrated_hint(media: dict) -> bool:
    """True when the media block records that measured operating points were available."""
    return bool(media.get("calibrated"))


def event_claim(media: dict, independent_corroboration: list[dict] | None = None) -> dict:
    """The claim media cannot make on its own, and the grade that admits it.

    An independent record does not need the footage's permission. Gating this behind the media
    grade, as this function used to, made a custody log less credible whenever the pixels were
    ambiguous, which is backwards: the record is the stronger evidence and the footage is the
    thing under attack.
    """
    corroboration = [c for c in (independent_corroboration or []) if c.get("independent")]
    if corroboration:
        grade = "corroborated"
        why = "an independent non-media source contradicts the event"
    else:
        grade = "unknown"
        why = "media alone cannot establish that an event did not happen"
    limits = list(media["limitations"])
    if not corroboration:
        limits.append("no independent non-media source contradicts the event")
    if not calibrated_hint(media):
        limits.append("media grade was capped by missing calibration")
    return {
        "claim": "event_false",
        "grade": grade,
        "reason": why,
        "media_grade": media["grade"],
        "calibrated": calibrated_hint(media),
        "limitations": limits,
    }


# ---------------------------------------------------------------- calibration ---


def fit_logistic(scores: list[float], labels: list[int], iters: int = 800, lr: float = 0.8):
    """Platt-style scaling by hand: two parameters, deterministic, no optimisation library."""
    w, b = 1.0, 0.0
    n = max(1, len(scores))
    for _ in range(iters):
        gw = gb = 0.0
        for x, y in zip(scores, labels):
            p = 1.0 / (1.0 + math.exp(-(w * x + b)))
            gw += (p - y) * x
            gb += (p - y)
        w -= lr * gw / n
        b -= lr * gb / n
    return round(w, 6), round(b, 6)


def probability(w: float, b: float, x: float) -> float:
    return 1.0 / (1.0 + math.exp(-(w * x + b)))


def brier(scores: list[float], labels: list[int], w: float = 1.0, b: float = 0.0) -> float:
    """Mean squared error of the stated probabilities. 0.25 is a coin that says 0.5."""
    if not scores:
        return float("nan")
    return sum((probability(w, b, s) - y) ** 2 for s, y in zip(scores, labels)) / len(scores)


def reliability(scores: list[float], labels: list[int], w: float = 1.0, b: float = 0.0, bins: int = 5):
    buckets: list[list[tuple[float, int]]] = [[] for _ in range(bins)]
    for s, y in zip(scores, labels):
        p = probability(w, b, s)
        buckets[min(bins - 1, int(p * bins))].append((p, y))
    return [
        {
            "bin": i,
            "n": len(v),
            "predicted": round(sum(p for p, _ in v) / len(v), 3),
            "observed": round(sum(y for _, y in v) / len(v), 3),
        }
        for i, v in enumerate(buckets)
        if v
    ]


def auc(scores: list[float], labels: list[int]) -> float:
    """Rank-based, ties averaged. 0.5 is a coin; 1.0 is a perfect separator."""
    pos = [s for s, y in zip(scores, labels) if y == 1]
    neg = [s for s, y in zip(scores, labels) if y == 0]
    if not pos or not neg:
        return float("nan")
    wins = 0.0
    for p in pos:
        for n in neg:
            wins += 1.0 if p > n else 0.5 if p == n else 0.0
    return wins / (len(pos) * len(neg))


def threshold_for_fpr(negative_scores: list[float], target: float = 0.05) -> float:
    """The threshold that flags at most `target` of authentic frames."""
    if not negative_scores:
        return float("inf")
    ordered = sorted(negative_scores, reverse=True)
    allowed = max(0, int(math.floor(target * len(ordered))))
    if allowed == 0:
        return ordered[0] + 1e-12  # nothing at or above the best authentic score
    if allowed >= len(ordered):
        return ordered[-1] - 1e-12  # everything is allowed
    # Midpoint between the last score we are willing to flag and the first we are not. Sitting on
    # one of them would flag it too, which is how a 5% target becomes 30% in practice.
    return (ordered[allowed - 1] + ordered[allowed]) / 2


# -------------------------------------------------------------- evaluation ---

#: Generator families. Each is a different way of building the same lie, which is what a holdout
#: is supposed to simulate: the next one will differ in a way nobody here has written down.
FAMILIES = {"smooth": 2.2, "light": 0.9, "hard": 0.0}
_SEED_BASE = {"smooth": 0, "light": 1000, "hard": 2000}


def _score(arr) -> float:
    raw = all_signals(arr)
    vals = [oriented(name, value) for name, value in raw.items()]
    return sum(vals) / len(vals)


def corpus(family: str, count: int = 8, size: int = 192) -> list[tuple[str, int, float]]:
    """(family, label, score) rows. Label 1 means manipulated."""
    base_seed = _SEED_BASE[family]
    rows: list[tuple[str, int, float]] = []
    for i in range(count):
        frame = synth.face_frame(seed=base_seed + i, size=size)
        rows.append((family, 0, _score(frame)))
        rows.append(
            (family, 1, _score(synth.manipulate(frame, seed=base_seed + 500 + i, blur=FAMILIES[family])))
        )
    return rows


def evaluate(holdout: str = "hard", count: int = 8, target_fpr: float = 0.05) -> dict:
    """Fit on the families available, then score the one held back.

    The holdout number is the only honest one. Everything else is the detector being asked about
    footage from generators it has already met.
    """
    train_rows = [row for name in FAMILIES if name != holdout for row in corpus(name, count=count)]
    hold_rows = corpus(holdout, count=count)

    tr_scores = [s for _, _, s in train_rows]
    tr_labels = [y for _, y, _ in train_rows]
    w, b = fit_logistic(tr_scores, tr_labels)
    threshold = threshold_for_fpr([s for s, y in zip(tr_scores, tr_labels) if y == 0], target_fpr)

    def summarise(rows):
        scores = [s for _, _, s in rows]
        labels = [y for _, y, _ in rows]
        flagged = [s >= threshold for s in scores]
        tp = sum(1 for f, y in zip(flagged, labels) if f and y == 1)
        fp = sum(1 for f, y in zip(flagged, labels) if f and y == 0)
        npos = sum(1 for y in labels if y == 1)
        nneg = sum(1 for y in labels if y == 0)
        return {
            "auc": round(auc(scores, labels), 3),
            "detection_rate": round(tp / npos, 3) if npos else None,
            "false_positive_rate": round(fp / nneg, 3) if nneg else None,
            "brier": round(brier(scores, labels, w, b), 3),
            "n": len(rows),
        }

    by_family = {name: summarise([r for r in train_rows if r[0] == name]) for name in FAMILIES if name != holdout}
    held = summarise(hold_rows)
    by_family[holdout] = held

    return {
        "holdout": holdout,
        "threshold": round(threshold, 4),
        "platt": {"w": w, "b": b},
        "target_fpr": target_fpr,
        "families": by_family,
        "reliability_holdout": reliability(
            [s for _, _, s in hold_rows], [y for _, y, _ in hold_rows], w, b
        ),
    }


if __name__ == "__main__":  # pragma: no cover
    import json

    result = evaluate()
    print(json.dumps(result, indent=2))
