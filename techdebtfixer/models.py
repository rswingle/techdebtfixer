"""Shared data model for techdebtfixer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    """A single observed signal gathered from the target environment."""

    check_id: str
    title: str
    category: str  # e.g. "security", "debt"
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    status: str  # "fail" | "warn" | "pass" | "unknown"
    detail: str = ""
    evidence: str = ""
    remediation: str = ""
    weight: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def debt_value(self) -> int:
        """Debt points contributed by this finding (0 when passing)."""
        return 0 if self.status == "pass" else self.weight_to_points

    @property
    def weight_to_points(self) -> int:
        return {
            "critical": 40,
            "high": 20,
            "medium": 10,
            "low": 5,
            "info": 0,
        }.get(self.severity, 5)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "status": self.status,
            "detail": self.detail,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "weight": self.weight,
            "metadata": self.metadata,
        }


@dataclass
class DebtItem:
    """A concrete piece of technical debt derived from failing findings."""

    key: str
    title: str
    category: str
    severity: str
    points: int
    description: str
    fix: str
    related_findings: list[str] = field(default_factory=list)


@dataclass
class CMMLevel:
    """One level of the Common Maturity Model."""

    level: int
    name: str
    description: str
    threshold: float  # minimum normalized score (0..1) to reach this level


CMM_LEVELS: list[CMMLevel] = [
    CMMLevel(
        1,
        "Initial",
        "Ad-hoc practices; security and debt controls are inconsistent and reactive.",
        0.00,
    ),
    CMMLevel(
        2,
        "Managed",
        "Basic practices exist in some teams but are undocumented and unevenly applied.",
        0.35,
    ),
    CMMLevel(
        3,
        "Defined",
        "Standardized, documented processes are adopted org-wide, incl. CI checks.",
        0.55,
    ),
    CMMLevel(
        4,
        "Quantitatively Managed",
        "Controls are measured with metrics; debt is tracked and trended.",
        0.75,
    ),
    CMMLevel(
        5,
        "Optimizing",
        "Continuous improvement; automation enforces policy and debt shrinks.",
        0.90,
    ),
]


@dataclass
class MaturityResult:
    """Outcome of scoring an assessment against the CMM."""

    score: float  # 0..100
    normalized: float  # 0..1
    level: CMMLevel
    next_level: CMMLevel | None
    points_to_next: int  # debt points that must be cleared to reach next level
    total_debt_points: int


@dataclass
class RoadmapStep:
    """One ordered action in the remediation roadmap."""

    order: int
    title: str
    category: str
    effort: str  # "S" | "M" | "L"
    impact: str  # human description of what improves
    addresses: list[str] = field(default_factory=list)  # finding check_ids
    unlocks_level: int | None = None

    def render(self) -> str:
        unlock = (
            f" (moves org to CMM L{self.unlocks_level})"
            if self.unlocks_level
            else ""
        )
        lines = [
            f"{self.order}. [{self.effort}] {self.title}{unlock}",
            f"   Impact: {self.impact}",
        ]
        if self.addresses:
            lines.append(f"   Addresses: {', '.join(self.addresses)}")
        return "\n".join(lines)


@dataclass
class Roadmap:
    """Ordered remediation plan grouped into phases."""

    phases: list[str] = field(default_factory=list)
    steps: list[RoadmapStep] = field(default_factory=list)

    def render(self) -> str:
        """Render steps grouped under their phase headers, in order."""
        if not self.steps:
            return "No roadmap steps needed - you are at CMM Level 5."
        out: list[str] = []
        seen: list[str] = []
        for step in self.steps:
            phase = getattr(step, "phase", "")
            if phase and phase not in seen:
                seen.append(phase)
                out.append(f"Phase: {phase}")
            out.append(step.render())
        return "\n\n".join(out)


@dataclass
class Assessment:
    """Full result of an assessment run against one target."""

    target: str
    connector: str
    findings: list[Finding] = field(default_factory=list)
    debt_items: list[DebtItem] = field(default_factory=list)
    maturity: MaturityResult | None = None
    roadmap: Roadmap | None = None
    summary: str = ""

    def total_debt_points(self) -> int:
        return sum(f.debt_value for f in self.findings)

    def by_category(self) -> dict[str, list[Finding]]:
        cats: dict[str, list[Finding]] = {}
        for f in self.findings:
            cats.setdefault(f.category, []).append(f)
        return cats

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.status] = out.get(f.status, 0) + 1
        return out
