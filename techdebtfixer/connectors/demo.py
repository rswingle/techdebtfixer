"""Demo connector: deterministic synthetic findings for a fictional org.

Always "authenticates" successfully, so the full pipeline (score -> maturity
-> roadmap -> report) can be exercised offline with zero credentials.
"""

from __future__ import annotations

from techdebtfixer.connectors.base import Connector, register
from techdebtfixer.models import Finding

# (check_id, title, category, severity, status, detail, remediation, weight)
_SYNTHETIC: list[tuple[str, str, str, str, str, str, str, float]] = [
    (
        "demo.mfa",
        "MFA enforced for all identity providers",
        "security",
        "critical",
        "fail",
        "3 of 42 accounts have MFA disabled; no SSO policy enforces it.",
        "Require MFA at the IdP and block legacy auth protocols.",
        3.0,
    ),
    (
        "demo.patching",
        "Server patching within SLA",
        "security",
        "high",
        "fail",
        "14 servers missing security updates older than 90 days.",
        "Enable automated patching and define a 30-day patch SLA.",
        2.0,
    ),
    (
        "demo.backups",
        "Backup restore testing",
        "security",
        "high",
        "warn",
        "Backups exist but last successful restore test was 14 months ago.",
        "Schedule quarterly restore tests and record the results.",
        2.0,
    ),
    (
        "demo.offboarding",
        "Leaver offboarding within 24h",
        "security",
        "medium",
        "fail",
        "Average account disable time after termination is 9 days.",
        "Automate HR-triggered deprovisioning with a 24h SLA.",
        1.5,
    ),
    (
        "demo.secrets-scan",
        "Secret scanning enabled on all repositories",
        "security",
        "high",
        "pass",
        "Secret scanning and push protection are on org-wide.",
        "",
        2.0,
    ),
    (
        "demo.tests",
        "Automated test coverage in CI",
        "debt",
        "medium",
        "fail",
        "Only 2 of 11 services run tests in CI; none measure coverage.",
        "Add test runs to CI pipelines; set a 60% coverage floor.",
        1.5,
    ),
    (
        "demo.deps",
        "Dependency update automation",
        "debt",
        "medium",
        "fail",
        "No automated dependency updates; 5 repos >2 major versions behind.",
        "Enable automated dependency PRs (e.g. Renovate/Dependabot).",
        1.5,
    ),
    (
        "demo.docs",
        "Runbook/documentation coverage",
        "debt",
        "low",
        "fail",
        "6 services lack any operational runbook.",
        "Create runbooks for on-call actions per service.",
        1.0,
    ),
    (
        "demo.monitoring",
        "Centralized monitoring and alerting",
        "security",
        "medium",
        "pass",
        "All production systems ship logs and alerts to a central platform.",
        "",
        1.5,
    ),
    (
        "demo.pipeline",
        "Deployment pipeline automation",
        "debt",
        "low",
        "warn",
        "3 services are still deployed by hand on a monthly cadence.",
        "Extend the existing CI/CD template to the remaining services.",
        1.0,
    ),
]


@register
class DemoConnector(Connector):
    """Synthetic org used for demos, tests and offline development."""

    name = "demo"

    def validate(self) -> None:
        # Accepts anything; credentials are not needed for the demo org.
        return None

    def gather(self) -> list[Finding]:
        return [
            Finding(
                check_id=cid,
                title=title,
                category=cat,
                severity=sev,
                status=status,
                detail=detail,
                remediation=rem,
                weight=weight,
                metadata={"synthetic": True},
            )
            for (cid, title, cat, sev, status, detail, rem, weight) in _SYNTHETIC
        ]
