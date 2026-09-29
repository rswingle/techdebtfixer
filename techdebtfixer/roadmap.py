"""Build an ordered remediation roadmap from failing findings."""

from __future__ import annotations

from techdebtfixer.models import Assessment, MaturityResult, Roadmap, RoadmapStep

EFFORT_BY_SEVERITY = {
    "critical": "L",
    "high": "M",
    "medium": "S",
    "low": "S",
    "info": "S",
}

PHASE_BY_SEVERITY = {
    "critical": "Phase 1 - Critical security gaps",
    "high": "Phase 2 - High-risk debt",
    "medium": "Phase 3 - Standardize and measure",
    "low": "Phase 4 - Optimize and automate",
    "info": "Phase 4 - Optimize and automate",
}


def build_roadmap(assessment: Assessment, maturity: MaturityResult) -> Roadmap:
    """Turn failing/warning findings into an ordered, phased plan.

    Critical and high items come first (they gate CMM progression), then
    medium items, then low/info polish. Steps that would clear the debt
    gap to the next CMM level are flagged with unlocks_level.
    """
    fails = [f for f in assessment.findings if f.status in ("fail", "warn")]
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    fails.sort(key=lambda f: (rank.get(f.severity, 9), f.category, f.check_id))

    steps: list[RoadmapStep] = []
    remaining_gap = (
        maturity.points_to_next if maturity.next_level is not None else 0
    )
    cleared = 0

    for i, f in enumerate(fails, start=1):
        unlocks: int | None = None
        if maturity.next_level is not None and remaining_gap > 0:
            cleared += f.debt_value
            if cleared >= remaining_gap:
                unlocks = maturity.next_level.level
                remaining_gap = 0

        step = RoadmapStep(
            order=i,
            title=_title_for(f),
            category=f.severity,
            effort=EFFORT_BY_SEVERITY.get(f.severity, "S"),
            impact=(
                f"Remediates a {f.severity}-severity {f.category} gap; "
                f"recovers up to {f.debt_value} debt points."
            ),
            addresses=[f.check_id],
            unlocks_level=unlocks,
        )
        # Attach phase so Roadmap.render can group steps.
        step.phase = PHASE_BY_SEVERITY.get(f.severity, "Phase 4 - Optimize and automate")  # type: ignore[attr-defined]
        steps.append(step)

    roadmap = Roadmap(
        phases=sorted({s.phase for s in steps}) if steps else [],  # type: ignore[attr-defined]
        steps=steps,
    )
    return roadmap


def _title_for(f) -> str:
    return f"Remediate: {f.title}"
