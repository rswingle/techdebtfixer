"""Tests for techdebtfixer: models, credentials, maturity, roadmap, demo run.

Runs on the stdlib unittest runner so the project stays zero-dependency:
    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from techdebtfixer.connectors import get_connector, registry
from techdebtfixer.connectors.base import ConnectorError
from techdebtfixer.credentials import (
    Credentials,
    CredentialsError,
    from_json,
    mask_secret,
)
from techdebtfixer.maturity import compute_maturity, normalized_score
from techdebtfixer.models import Assessment, Finding, Roadmap
from techdebtfixer.pipeline import run_assessment
from techdebtfixer.report import render_json, render_text
from techdebtfixer.roadmap import build_roadmap


class FindingTests(unittest.TestCase):
    def test_debt_value_zero_when_pass(self) -> None:
        f = Finding("x", "t", "security", "high", "pass", weight=2.0)
        self.assertEqual(f.debt_value, 0)

    def test_debt_value_by_severity(self) -> None:
        self.assertEqual(Finding("x", "t", "s", "critical", "fail").debt_value, 40)
        self.assertEqual(Finding("x", "t", "s", "high", "warn").debt_value, 20)
        self.assertEqual(Finding("x", "t", "s", "low", "fail").debt_value, 5)

    def test_roadmap_render_empty_is_level5(self) -> None:
        self.assertIn("Level 5", Roadmap().render())


class CredentialsTests(unittest.TestCase):
    def test_mask_secret_hides_middle(self) -> None:
        masked = mask_secret("ghp_abcdefghijklmnopqrstuvwxyz")
        self.assertIn("ghp", masked)
        self.assertIn("xyz", masked)
        self.assertNotIn("abcdefghijklmnop", masked)

    def test_mask_secret_short(self) -> None:
        self.assertEqual(mask_secret("abc"), "•••")

    def test_from_json_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "creds.json"
            p.write_text(json.dumps({"token": "tok123"}))
            creds = from_json(str(p))
        self.assertEqual(creds.token, "tok123")
        self.assertEqual(creds.kind(), "token")

    def test_from_json_rejects_empty(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "creds.json"
            p.write_text(json.dumps({"note": "nothing useful"}))
            with self.assertRaises(CredentialsError):
                from_json(str(p))

    def test_masked_output_never_leaks(self) -> None:
        c = Credentials(username="alice", password="supersecret", token="ghp_secret")
        s = c.masked()
        self.assertNotIn("supersecret", s)
        self.assertNotIn("ghp_secret", s)


class MaturityTests(unittest.TestCase):
    def test_all_pass_scores_one(self) -> None:
        findings = [
            Finding("a", "a", "security", "high", "pass", weight=2.0),
            Finding("b", "b", "debt", "low", "pass", weight=1.0),
        ]
        self.assertEqual(normalized_score(findings), 1.0)

    def test_unknown_skipped(self) -> None:
        findings = [
            Finding("a", "a", "security", "high", "pass", weight=2.0),
            Finding("b", "b", "debt", "low", "unknown", weight=10.0),
        ]
        self.assertEqual(normalized_score(findings), 1.0)

    def test_warn_counts_half(self) -> None:
        findings = [Finding("a", "a", "security", "high", "warn", weight=2.0)]
        self.assertEqual(normalized_score(findings), 0.5)

    def test_perfect_score_is_level_five(self) -> None:
        a = Assessment(target="t", connector="demo")
        a.findings = [Finding("a", "a", "security", "low", "pass", weight=1.0)]
        m = compute_maturity(a)
        self.assertEqual(m.level.level, 5)
        self.assertIsNone(m.next_level)
        self.assertEqual(m.points_to_next, 0)

    def test_mixed_findings_low_level(self) -> None:
        a = Assessment(target="t", connector="demo")
        a.findings = [
            Finding("a", "a", "security", "critical", "fail", weight=3.0),
            Finding("b", "b", "security", "high", "pass", weight=2.0),
        ]
        m = compute_maturity(a)
        self.assertLessEqual(m.level.level, 2)
        self.assertEqual(m.total_debt_points, 40)


def _assessment_with(fail_sevs: list[str]) -> Assessment:
    a = Assessment(target="t", connector="demo")
    a.findings = [
        Finding(f"f{i}", f"f{i}", "security", sev, "fail", weight=1.0)
        for i, sev in enumerate(fail_sevs)
    ]
    a.findings.append(Finding("ok", "ok", "security", "low", "pass", weight=1.0))
    a.maturity = compute_maturity(a)
    return a


class RoadmapTests(unittest.TestCase):
    def test_orders_critical_first(self) -> None:
        a = _assessment_with(["low", "critical", "medium"])
        r = build_roadmap(a, a.maturity)
        self.assertEqual(r.steps[0].category, "critical")
        self.assertEqual([s.order for s in r.steps], [1, 2, 3])

    def test_flags_level_unlock(self) -> None:
        a = _assessment_with(["critical", "high", "high", "medium", "medium"])
        r = build_roadmap(a, a.maturity)
        self.assertTrue(any(s.unlocks_level is not None for s in r.steps))

    def test_render_groups_phases(self) -> None:
        a = _assessment_with(["critical", "low"])
        r = build_roadmap(a, a.maturity)
        text = r.render()
        self.assertIn("Phase:", text)
        self.assertIn("1. ", text)


class RegistryTests(unittest.TestCase):
    def test_builtin_connectors_registered(self) -> None:
        for name in ("demo", "github", "web", "local"):
            self.assertIn(name, registry)

    def test_unknown_connector_raises(self) -> None:
        with self.assertRaises(ConnectorError):
            get_connector("does-not-exist")


class DemoEndToEndTests(unittest.TestCase):
    def test_full_pipeline(self) -> None:
        cls = get_connector("demo")
        conn = cls(Credentials(), "demo-org")
        a = run_assessment(conn, conn.creds)

        self.assertTrue(a.findings, "demo connector must produce findings")
        self.assertIsNotNone(a.maturity)
        self.assertTrue(1 <= a.maturity.level.level <= 5)
        self.assertTrue(a.debt_items, "demo org has failing checks -> debt expected")
        self.assertTrue(a.roadmap is not None and a.roadmap.steps)

        text = render_text(a)
        for marker in ("CMM level", "TECHNICAL DEBT", "ROADMAP", "Phase:"):
            self.assertIn(marker, text)

        payload = json.loads(render_json(a))
        self.assertEqual(
            payload["maturity"]["level"]["level"], a.maturity.level.level
        )
        self.assertTrue(payload["findings"][0]["check_id"])

    def test_demo_is_deterministic(self) -> None:
        cls = get_connector("demo")
        a1 = run_assessment(cls(Credentials(), "x"), None)
        a2 = run_assessment(cls(Credentials(), "x"), None)
        self.assertEqual(
            [f.check_id for f in a1.findings], [f.check_id for f in a2.findings]
        )
        self.assertEqual(a1.maturity.score, a2.maturity.score)


if __name__ == "__main__":
    unittest.main()
