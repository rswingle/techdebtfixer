"""Human-readable report rendering for the CLI and saved reports."""

from __future__ import annotations

from techdebtfixer.models import Assessment
from techdebtfixer.maturity import failing_findings

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _bar(pct: float, width: int = 30) -> str:
    filled = int(round(max(0.0, min(1.0, pct)) * width))
    return "#" * filled + "." * (width - filled)


def render_text(assessment: Assessment) -> str:
    """Render a full assessment report as plain text."""
    out: list[str] = []
    m = assessment.maturity

    out.append("=" * 62)
    out.append("TECHDEBTFIXER ASSESSMENT REPORT")
    out.append("=" * 62)
    out.append(f"Target    : {assessment.target}")
    out.append(f"Connector : {assessment.connector}")
    out.append("")

    if m is not None:
        out.append("-- MATURITY (Common Maturity Model) " + "-" * 30)
        out.append(f"Posture score : {m.score}/100  {_bar(m.normalized)}")
        out.append(
            f"CMM level     : L{m.level.level} - {m.level.name}"
            f"  (threshold {m.level.threshold:.2f})"
        )
        out.append(f"  {m.level.description}")
        if m.next_level is not None:
            out.append(
                f"Next level    : L{m.next_level.level} - {m.next_level.name}"
                f"  ({m.points_to_next} debt points to clear)"
            )
        else:
            out.append("Next level    : none - already at the top of the model.")
        out.append(f"Total debt    : {m.total_debt_points} points")
        out.append("")

    counts = assessment.counts()
    out.append("-- FINDINGS SUMMARY " + "-" * 41)
    out.append(
        "  "
        + "  ".join(f"{k}: {v}" for k, v in sorted(counts.items()))
    )
    out.append("")

    out.append("-- TECHNICAL DEBT (worst first) " + "-" * 31)
    fails = failing_findings(assessment)
    if not fails:
        out.append("  No failing checks - no technical debt recorded.")
    for f in fails:
        marker = {"fail": "[FAIL]", "warn": "[WARN]"}.get(f.status, "[????]")
        out.append(f"  {marker} {f.severity.upper():<8} {f.title}")
        if f.detail:
            out.append(f"          {f.detail}")
        if f.remediation:
            out.append(f"          Fix: {f.remediation}")
    out.append("")

    out.append("-- ROADMAP " + "-" * 51)
    if assessment.roadmap is not None:
        out.append(assessment.roadmap.render())
    else:
        out.append("  (no roadmap generated)")
    out.append("")
    out.append("=" * 62)
    out.append("End of report.")
    return "\n".join(out)


def render_json(assessment: Assessment) -> str:
    """Render the assessment as machine-readable JSON."""
    import json

    m = assessment.maturity
    payload = {
        "target": assessment.target,
        "connector": assessment.connector,
        "summary": assessment.summary,
        "maturity": None
        if m is None
        else {
            "score": m.score,
            "normalized": m.normalized,
            "level": {"level": m.level.level, "name": m.level.name},
            "next_level": None
            if m.next_level is None
            else {"level": m.next_level.level, "name": m.next_level.name},
            "points_to_next": m.points_to_next,
            "total_debt_points": m.total_debt_points,
        },
        "counts": assessment.counts(),
        "findings": [f.to_dict() for f in assessment.findings],
        "debt_items": [
            {
                "key": d.key,
                "title": d.title,
                "category": d.category,
                "severity": d.severity,
                "points": d.points,
                "description": d.description,
                "fix": d.fix,
                "related_findings": d.related_findings,
            }
            for d in assessment.debt_items
        ],
        "roadmap": None
        if assessment.roadmap is None
        else {
            "phases": assessment.roadmap.phases,
            "steps": [
                {
                    "order": s.order,
                    "title": s.title,
                    "category": s.category,
                    "effort": s.effort,
                    "impact": s.impact,
                    "addresses": s.addresses,
                    "unlocks_level": s.unlocks_level,
                    "phase": getattr(s, "phase", ""),
                }
                for s in assessment.roadmap.steps
            ],
        },
    }
    return json.dumps(payload, indent=2)
