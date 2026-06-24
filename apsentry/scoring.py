"""Risk aggregation: turn a set of detections into an environment risk score."""
from __future__ import annotations

from .models import Detection, Severity

# Relative weight of each severity when computing the environment score.
_SEV_WEIGHT = {
    Severity.INFO: 1,
    Severity.LOW: 6,
    Severity.MEDIUM: 18,
    Severity.HIGH: 38,
    Severity.CRITICAL: 70,
}


def environment_risk(detections: list[Detection]) -> int:
    """0-100 overall risk, dominated by the worst findings but additive."""
    if not detections:
        return 0
    worst = max(int(d.severity) for d in detections)
    base = _SEV_WEIGHT[Severity(worst)]
    extra = sum(_SEV_WEIGHT[d.severity] for d in detections) - base
    score = base + extra * 0.35
    return int(max(0, min(100, score)))


def risk_label(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 30:
        return "elevated"
    if score >= 10:
        return "guarded"
    return "clear"
