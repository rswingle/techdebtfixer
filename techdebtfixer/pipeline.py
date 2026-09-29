"""Assessment pipeline: connector -> findings -> maturity -> roadmap -> report."""

from __future__ import annotations

from techdebtfixer.connectors.base import Connector, ConnectorError
from techdebtfixer.credentials import Credentials
from techdebtfixer.maturity import compute_maturity
from techdebtfixer.models import Assessment, DebtItem
from techdebtfixer.roadmap import build_roadmap


def run_assessment(
    connector: Connector,
    credentials: Credentials | None = None,
) -> Assessment:
    """Run the full pipeline against one target and return a finished Assessment."""
    connector.validate()
    findings = connector.gather()

    assessment = connector.build_assessment(findings)
    assessment.maturity = compute_maturity(assessment)

    # Derive debt items from failing findings (worst first).
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    fails = [
        f
        for f in assessment.findings
        if f.status in ("fail", "warn") and f.debt_value > 0
    ]
    fails.sort(key=lambda f: (rank.get(f.severity, 9), f.category))
    assessment.debt_items = [
        DebtItem(
            key=f.check_id,
            title=f.title,
            category=f.category,
            severity=f.severity,
            points=f.debt_value,
            description=f.detail or f.title,
            fix=f.remediation,
            related_findings=[f.check_id],
        )
        for f in fails
    ]

    assessment.roadmap = build_roadmap(assessment, assessment.maturity)
    assessment.summary = _summary_line(assessment)
    return assessment


def _summary_line(assessment: Assessment) -> str:
    m = assessment.maturity
    counts = assessment.counts()
    if m is None:
        return "Assessment incomplete."
    nxt = (
        f"next: L{m.next_level.level} {m.next_level.name}"
        if m.next_level is not None
        else "top level reached"
    )
    return (
        f"CMM L{m.level.level} {m.level.name} ({m.score}/100), "
        f"debt {m.total_debt_points} pts "
        f"(fails={counts.get('fail', 0)}, warns={counts.get('warn', 0)}, "
        f"passes={counts.get('pass', 0)}); {nxt}"
    )
