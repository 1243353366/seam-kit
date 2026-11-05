"""Turning three weak signals into one honest sentence.

No single metric here is a detector. Each is a reason to look. What the report gives you is how
many independent reasons pointed the same way, and what would explain them without a fake.
"""
from __future__ import annotations

#: Used only when no calibration has been run. These are inherited guesses and are labelled as
#: such in every report that relies on them.
DEFAULTS = {
    "ela_ratio": 3.0,
    "ela_hot_share": 0.02,
    "spectrum_prominence": 6.0,
    "noise_deviation": 0.15,
}

VERDICTS = ("clean", "suspect", "unexplained")


def _verdict(flag: bool, *, unexplained: bool = False) -> str:
    if flag:
        return "suspect"
    return "unexplained" if unexplained else "clean"


def assess(metrics: dict, calibration: dict | None = None) -> dict:
    stats = (calibration or {}).get("stats", {})
    ela_ratio_limit = max(DEFAULTS["ela_ratio"], stats.get("ela_ratio", {}).get("max", 0.0))
    prominence_limit = max(
        DEFAULTS["spectrum_prominence"], stats.get("spectrum_prominence", {}).get("max", 0.0)
    )
    noise_ref = stats.get("noise_ratio", {}).get("mean")
    noise_sd = max(stats.get("noise_ratio", {}).get("sd", 0.0), 0.01)
    noise_deviation = (
        abs(metrics["noise_ratio"] - noise_ref) / noise_sd if noise_ref is not None else None
    )

    # A pasted patch is cold when it arrived already quantised and hot when it arrived raw, so
    # the signal is "a coherent region disagrees with the frame", in either direction.
    disagreeing = max(metrics.get("ela_hot_share", 0.0), metrics.get("ela_cold_share", 0.0))
    ela = _verdict(
        disagreeing >= DEFAULTS["ela_hot_share"] and not metrics.get("ela_quiet", False)
    )
    if metrics["spectrum_near_jpeg"]:
        # 8 px blocking explains the peak. Calling it a hit here is the classic false positive.
        spectrum = "unexplained"
    else:
        spectrum = _verdict(metrics["spectrum_prominence"] >= prominence_limit)

    if noise_deviation is None:
        noise = _verdict(metrics["noise_ratio"] < 0.85 or metrics["noise_ratio"] > 1.15)
        noise_basis = "defaults"
    else:
        noise = _verdict(noise_deviation >= 3.0)
        noise_basis = "calibration"

    verdicts = {"ela": ela, "spectrum": spectrum, "noise": noise}
    hits = sum(1 for v in verdicts.values() if v == "suspect")
    if hits >= 2:
        headline = "worth a second look: more than one independent tell"
    elif hits == 1:
        headline = "one tell only: noise, not evidence"
    else:
        headline = "no tell in these three checks, which is not the same as authentic"

    return {
        "verdicts": verdicts,
        "hits": hits,
        "headline": headline,
        "calibrated": calibration is not None,
        "noise_basis": noise_basis,
        "limits": {
            "ela_ratio": ela_ratio_limit,
            "spectrum_prominence": prominence_limit,
            "noise_sd_multiple": 3.0,
        },
        "jpeg_blocking_detected": bool(metrics["spectrum_near_jpeg"]),
    }


def render(metrics: dict, assessment: dict) -> str:
    lines = [
        f"image      {metrics['width']}x{metrics['height']}  ({metrics['path']})",
        f"headline   {assessment['headline']}",
        "",
        f"  ela        {assessment['verdicts']['ela']:<12} ratio {metrics['ela_ratio']}"
        f"  limit {assessment['limits']['ela_ratio']}",
        f"  spectrum   {assessment['verdicts']['spectrum']:<12} period {metrics['spectrum_period']}px"
        f"  prominence {metrics['spectrum_prominence']}",
        f"  noise      {assessment['verdicts']['noise']:<12} ratio {metrics['noise_ratio']}"
        f"  basis {assessment['noise_basis']}",
    ]
    if assessment["jpeg_blocking_detected"]:
        lines.append("             the spectrum peak sits at 8 px: JPEG blocking, not a generator")
    if not assessment["calibrated"]:
        lines.append("             thresholds are inherited guesses; run `calibrate` on real images")
    lines.append("")
    lines.append("  one tell is noise. two is worth a second look. three is a pattern.")
    lines.append("  none of it is proof, and a fake can be built to pass all three.")
    return "\n".join(lines)
