"""Headless TUI smoke tests using Textual's pilot (async test runner)."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from techdebtfixer.vault import ScanRecord, Vault, VaultError

try:
    import textual  # noqa: F401

    HAS_TEXTUAL = True
except ImportError:  # pragma: no cover
    HAS_TEXTUAL = False

if HAS_TEXTUAL:
    from textual.widgets import Input, Tree

    from techdebtfixer.tui import UnlockScreen, VaultTui, sparkline


class _AsyncCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.vault_path = Path(self._tmp.name) / "t.vault.json"

    async def _run_app(self) -> VaultTui:
        app = VaultTui(Vault(self.vault_path))
        self.addCleanup(app._shutdown)
        async with app.run_test() as pilot:
            self.app = app
            self.pilot = pilot
            # Let on_mount screen push settle.
            await pilot.pause()
            yield  # body runs inside the context
        # after context exit the app is stopped


@unittest.skipUnless(HAS_TEXTUAL, "textual not installed")
class UnlockFlowTests(_AsyncCase):
    async def test_first_run_shows_create_prompt(self) -> None:
        async for _ in self._run_app():
            screen = self.app.screen
            self.assertIsInstance(screen, UnlockScreen)
            label = str(screen.query_one(".modal-title").render())
            self.assertIn("Create a new vault", label)
            self.assertFalse(self.vault_path.exists())

    async def test_create_vault_through_prompts(self) -> None:
        async for _ in self._run_app():
            screen = self.app.screen
            self.assertIsInstance(screen, UnlockScreen)
            pw1 = screen.query_one("#pw1", Input)
            pw1.value = "first-run-pw"
            screen.query_one("#pw2", Input).value = "first-run-pw"
            screen.query_one("#go-btn").press()
            await self.pilot.pause()
            self.assertTrue(self.vault_path.exists())
            self.assertTrue(self.app.vault.unlocked)
            # Modal dismissed, main screen with tree is active.
            self.assertNotIsInstance(self.app.screen, UnlockScreen)
            tree = self.app.query_one("#client-tree")
            self.assertIsNotNone(tree)
            # Vault on disk unlocks with the same password.
            again = Vault(self.vault_path)
            again.unlock("first-run-pw")
            self.assertTrue(again.unlocked)

    async def test_mismatched_passwords_do_not_create(self) -> None:
        async for _ in self._run_app():
            screen = self.app.screen
            self.assertIsInstance(screen, UnlockScreen)
            screen.query_one("#pw1", Input).value = "pw-a"
            screen.query_one("#pw2", Input).value = "pw-b"
            screen.query_one("#go-btn").press()
            await self.pilot.pause()
            self.assertFalse(self.vault_path.exists())
            self.assertIsInstance(self.app.screen, UnlockScreen)


@unittest.skipUnless(HAS_TEXTUAL, "textual not installed")
class LockedFlowTests(_AsyncCase):
    async def test_existing_vault_shows_unlock_prompt(self) -> None:
        vault = Vault(self.vault_path)
        vault.create("existing-pw")
        vault.add_client("Acme")
        vault.lock()

        app = VaultTui(Vault(self.vault_path))
        self.addCleanup(app._shutdown)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = app.screen
            self.assertIsInstance(screen, UnlockScreen)
            label = str(screen.query_one(".modal-title").render())
            self.assertIn("Vault locked", label)
            screen.query_one("#pw1", Input).value = "existing-pw"
            screen.query_one("#go-btn").press()
            await pilot.pause()
            self.assertTrue(app.vault.unlocked)
            tree = app.query_one("#client-tree")
            labels = [str(child.label) for child in tree.root.children]
            self.assertIn("Acme", labels)

    async def test_wrong_password_stays_locked(self) -> None:
        vault = Vault(self.vault_path)
        vault.create("right-pw")
        vault.lock()

        app = VaultTui(Vault(self.vault_path))
        self.addCleanup(app._shutdown)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = app.screen
            screen.query_one("#pw1", Input).value = "wrong-pw"
            screen.query_one("#go-btn").press()
            await pilot.pause()
            self.assertFalse(app.vault.unlocked)
            self.assertIsInstance(app.screen, UnlockScreen)


@unittest.skipUnless(HAS_TEXTUAL, "textual not installed")
class SparklineTests(unittest.TestCase):
    def test_empty(self) -> None:
        self.assertEqual(sparkline([]), "")

    def test_single_and_bounds(self) -> None:
        self.assertEqual(sparkline([0.0]), "▁")
        self.assertEqual(sparkline([100.0]), "█")
        self.assertEqual(sparkline([50.0]), "▅")  # 3.5 rounds to even (4)

    def test_clamps_out_of_range(self) -> None:
        self.assertEqual(sparkline([-10.0, 110.0]), "▁█")

    def test_rising_trend_renders_rising_bars(self) -> None:
        bars = sparkline([10.0, 50.0, 90.0])
        self.assertEqual(bars, "▂▅▇")


@unittest.skipUnless(HAS_TEXTUAL, "textual not installed")
class AssessmentFlowTests(_AsyncCase):
    async def test_set_target_and_run_demo_scan(self) -> None:
        from textual.widgets import Button

        vault = Vault(self.vault_path)
        vault.create("pw")
        client = vault.add_client("Acme")
        project = vault.add_project(client.id, "Core API")
        vault.lock()

        app = VaultTui(Vault(self.vault_path))
        self.addCleanup(app._shutdown)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            screen = app.screen
            screen.query_one("#pw1", Input).value = "pw"
            screen.query_one("#go-btn").press()
            await pilot.pause()
            self.assertTrue(app.vault.unlocked)

            # Configure the scan target through the modal form.
            tree = app.query_one("#client-tree")
            def find(node, text):
                for child in node.children:
                    if text in str(child.label):
                        return child
                    found = find(child, text)
                    if found:
                        return found
                return None
            tree.select_node(find(tree.root, "Core API"))
            await pilot.pause()

            app.action_set_target()
            await pilot.pause()
            from textual.widgets import Input as In

            modal = app.screen
            modal.query_one("#field-connector", In).value = "demo"
            modal.query_one("#field-target", In).value = "demo-org"
            modal.query_one("#save-btn", Button).press()
            await pilot.pause()
            stored = app.vault.get_project(client.id, project.id)
            self.assertEqual(stored.connector, "demo")
            self.assertEqual(stored.target, "demo-org")

            # Run the assessment; the demo connector works offline.
            app.action_run_assessment()
            for _ in range(50):  # up to ~5s for the worker thread
                await pilot.pause(0.1)
                if app.vault.get_project(client.id, project.id).last_scan:
                    break
            scan = app.vault.get_project(client.id, project.id).last_scan
            self.assertIsNotNone(scan, "scan result was not recorded")
            self.assertEqual(scan.connector, "demo")
            self.assertEqual(scan.target, "demo-org")
            self.assertTrue(1 <= scan.cmm_level <= 5)

    async def test_scan_history_screen_shows_trend(self) -> None:
        from datetime import datetime, timedelta, timezone
        from textual.widgets import Button

        vault = Vault(self.vault_path)
        vault.create("pw")
        client = vault.add_client("Acme")
        project = vault.add_project(client.id, "Core API")
        vault.set_project_scan_config(client.id, project.id, "demo", "demo-org")
        base = datetime.now(timezone.utc)
        for i, (score, debt) in enumerate(((41.2, 95), (55.0, 60))):
            vault.record_scan_result(
                client.id, project.id,
                ScanRecord(
                    at=(base + timedelta(hours=i)).isoformat(timespec="seconds"),
                    connector="demo", target="demo-org",
                    cmm_level=2 if i == 0 else 3,
                    cmm_name="Managed" if i == 0 else "Defined",
                    score=score, debt_points=debt,
                ),
            )
        vault.lock()

        app = VaultTui(Vault(self.vault_path))
        self.addCleanup(app._shutdown)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            screen = app.screen
            screen.query_one("#pw1", Input).value = "pw"
            screen.query_one("#go-btn").press()
            await pilot.pause()

            tree = app.query_one("#client-tree")
            def find(node, text):
                for child in node.children:
                    if text in str(child.label):
                        return child
                    found = find(child, text)
                    if found:
                        return found
                return None
            tree.select_node(find(tree.root, "Core API"))
            await pilot.pause()

            # Detail pane shows the trend line.
            detail = str(app.query_one("#detail").render())
            self.assertIn("trend vs previous", detail)
            self.assertIn("scans recorded: 2", detail)

            # History screen lists both scans with the trend arrow.
            from techdebtfixer.tui import ScanHistoryScreen

            app.action_scan_history()
            for _ in range(20):  # wait for the push to install + compose
                await pilot.pause()
                if isinstance(app.screen, ScanHistoryScreen):
                    break
            self.assertIsInstance(app.screen, ScanHistoryScreen)
            history_text = str(app.screen.query_one("#history-text").render())
            self.assertIn("Scan history - Core API", history_text)
            self.assertIn("▲", history_text)
            self.assertIn("score +13.8", history_text)
            self.assertIn("CMM L3", history_text)
            self.assertIn("score over time", history_text)
            self.assertIn("▄▅", history_text)  # sparkline: 41.2->▄, 55.0->▅

    async def test_assess_without_target_warns(self) -> None:
        vault = Vault(self.vault_path)
        vault.create("pw")
        client = vault.add_client("Acme")
        vault.add_project(client.id, "No Target")
        vault.lock()

        app = VaultTui(Vault(self.vault_path))
        self.addCleanup(app._shutdown)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = app.screen
            screen.query_one("#pw1", Input).value = "pw"
            screen.query_one("#go-btn").press()
            await pilot.pause()

            tree = app.query_one("#client-tree")
            def find(node, text):
                for child in node.children:
                    if text in str(child.label):
                        return child
                    found = find(child, text)
                    if found:
                        return found
                return None
            tree.select_node(find(tree.root, "No Target"))
            await pilot.pause()
            app.action_run_assessment()  # must not raise or push ScanScreen
            await pilot.pause()
            from techdebtfixer.tui import ScanScreen

            self.assertNotIsInstance(app.screen, ScanScreen)


@unittest.skipUnless(HAS_TEXTUAL, "textual not installed")
class RotationMarkerTests(_AsyncCase):
    async def test_overdue_marker_appears_in_tree(self) -> None:
        from datetime import datetime, timedelta, timezone

        vault = Vault(self.vault_path)
        vault.create("pw")
        client = vault.add_client("Marker Co")
        old = vault.add_secret(
            client.id, None, name="stale key", secret="v", rotate_days=30
        )
        old.last_rotated = (
            datetime.now(timezone.utc) - timedelta(days=60)
        ).isoformat()
        vault.save()
        vault.lock()

        app = VaultTui(Vault(self.vault_path))
        self.addCleanup(app._shutdown)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = app.screen
            screen.query_one("#pw1", Input).value = "pw"
            screen.query_one("#go-btn").press()
            await pilot.pause()

            tree = app.query_one("#client-tree", Tree)
            labels = [str(child.label) for child in tree.root.children]
            self.assertTrue(
                any("Marker Co" in label for label in labels), labels
            )
            client_node = next(
                child
                for child in tree.root.children
                if "Marker Co" in str(child.label)
            )
            secret_labels = [str(c.label) for c in client_node.children]
            self.assertTrue(
                any("overdue" in label for label in secret_labels),
                secret_labels,
            )
            # Root detail shows the rotation summary counts.
            tree.select_node(tree.root)
            await pilot.pause()
            detail = str(app.query_one("#detail").render())
            self.assertIn("rotation overdue", detail)


if __name__ == "__main__":
    unittest.main()
