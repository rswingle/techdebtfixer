"""Common Maturity Model definitions and the weighted scoring engine."""

from __future__ import annotations

from techdebtfixer.models import (
    Assessment,
    CMM_LEVELS,
    CMMLevel,
    Finding,
    MaturityResult,
)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def normalized_score(findings: list[Finding]) -> float:
    """Compute a 0..1 posture score from findings.

    Passing checks contribute their weight; failing checks contribute nothing.
    Checks with status 'unknown' are skipped entirely (they don't help or hurt).
    """
    total_weight = 0.0
    earned = 0.0
    for f in findings:
        if f.status == "unknown":
            continue
        total_weight += f.weight
        if f.status == "pass":
            earned += f.weight
        elif f.status == "warn":
            earned += f.weight * 0.5
    if total_weight <= 0:
        return 0.0
    return earned / total_weight


def compute_maturity(assessment: Assessment) -> MaturityResult:
    """Score the assessment and place the org on the CMM."""
    norm = normalized_score(assessment.findings)
    score = round(norm * 100, 1)

    level = CMM_LEVELS[0]
    for lvl in CMM_LEVELS:
        if norm >= lvl.threshold:
            level = lvl
    idx = CMM_LEVELS.index(level)
    nxt = CMM_LEVELS[idx + 1] if idx + 1 < len(CMM_LEVELS) else None

    total_debt = assessment.total_debt_points()

    if nxt is not None:
        gap = nxt.threshold - norm
        # Rough conversion: each debt point ≈ 1 point of posture recovery.
        points_to_next = max(1, round(gap * 100))
    else:
        points_to_next = 0

    return MaturityResult(
        score=score,
        normalized=norm,
        level=level,
        next_level=nxt,
        points_to_next=points_to_next,
        total_debt_points=total_debt,
    )


def next_level_gap(findings: list[Finding], target_level: CMMLevel) -> float:
    """How much normalized score is missing to reach a given level."""
    return max(0.0, target_level.threshold - normalized_score(findings))


def failing_findings(assessment: Assessment) -> list[Finding]:
    """Failures sorted worst-first using CMM severity ordering."""
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    fails = [f for f in assessment.findings if f.status in ("fail", "warn")]
    return sorted(fails, key=lambda f: (rank.get(f.severity, 99), f.category))
