"""Headless TUI smoke tests using Textual's pilot (async test runner)."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from techdebtfixer.vault import Vault, VaultError

try:
    import textual  # noqa: F401

    HAS_TEXTUAL = True
except ImportError:  # pragma: no cover
    HAS_TEXTUAL = False

if HAS_TEXTUAL:
    from textual.widgets import Input, Tree

    from techdebtfixer.tui import UnlockScreen, VaultTui


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
