"""Tests for the encrypted vault and the TUI module import surface."""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from techdebtfixer.vault import (
    Project,
    ScanRecord,
    Vault,
    VaultError,
    rotation_report,
    rotation_status,
)

try:  # cryptography is required for the vault; skip cleanly without it
    import cryptography  # noqa: F401

    HAS_CRYPTO = True
except ImportError:  # pragma: no cover
    HAS_CRYPTO = False


@unittest.skipUnless(HAS_CRYPTO, "cryptography package not installed")
class VaultTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "test.vault.json"

    def _new_vault(self) -> Vault:
        vault = Vault(self.path)
        vault.create("hunter2!")
        return vault

    def test_create_writes_encrypted_file(self) -> None:
        vault = self._new_vault()
        self.assertTrue(vault.exists)
        self.assertTrue(vault.unlocked)
        raw = self.path.read_text(encoding="utf-8")
        self.assertNotIn("hunter2", raw)
        self.assertIn('"ciphertext"', raw)
        self.assertIn('"PBKDF2-HMAC-SHA256"', raw)

    def test_roundtrip_unlock(self) -> None:
        vault = self._new_vault()
        client = vault.add_client("Acme Corp")
        project = vault.add_project(client.id, "Website Revamp")
        vault.add_secret(
            client.id, project.id,
            name="staging api key", kind="api-key",
            username="deploy-bot", secret="s3cr3t-value",
            notes="rotate quarterly",
        )

        again = Vault(self.path)
        with self.assertRaises(VaultError):
            again.data  # locked
        with self.assertRaises(VaultError):
            again.unlock("wrong-password")
        again.unlock("hunter2!")
        loaded = again.get_client(client.id)
        self.assertEqual(loaded.name, "Acme Corp")
        loaded_project = again.get_project(client.id, project.id)
        entry = next(iter(loaded_project.secrets.values()))
        self.assertEqual(entry.secret.decode(), "s3cr3t-value")
        self.assertEqual(entry.username, "deploy-bot")

    def test_wrong_password_leaves_vault_locked(self) -> None:
        self._new_vault()
        vault = Vault(self.path)
        with self.assertRaises(VaultError):
            vault.unlock("nope")
        self.assertFalse(vault.unlocked)

    def test_client_project_secret_crud(self) -> None:
        vault = self._new_vault()
        client = vault.add_client("Globex")
        with self.assertRaises(VaultError):
            vault.add_client("  ")  # blank names rejected

        project = vault.add_project(client.id, "Mobile App")
        vault.rename_project(client.id, project.id, "Mobile App v2")
        self.assertEqual(
            vault.get_project(client.id, project.id).name, "Mobile App v2"
        )

        secret = vault.add_secret(client.id, None, name="oauth token",
                                  secret="tok123")
        vault.update_secret(client.id, None, secret.id, secret="tok456")
        self.assertEqual(
            vault.get_secret(client.id, None, secret.id).secret.decode(),
            "tok456",
        )
        vault.delete_secret(client.id, None, secret.id)
        vault.delete_project(client.id, project.id)
        vault.delete_client(client.id)
        self.assertEqual(len(vault.data.clients), 0)

    def test_unfiled_secrets(self) -> None:
        vault = self._new_vault()
        entry = vault.add_secret("", None, name="misc key", secret="abc")
        self.assertIn(entry.id, vault.data.secrets)
        vault.update_secret("", None, entry.id, notes="personal")
        vault.delete_secret("", None, entry.id)
        self.assertEqual(len(vault.data.secrets), 0)

    def test_file_permissions_restricted(self) -> None:
        self._new_vault()
        mode = os.stat(self.path).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_lock_clears_plaintext(self) -> None:
        vault = self._new_vault()
        vault.add_client("Initech")
        vault.lock()
        self.assertFalse(vault.unlocked)
        with self.assertRaises(VaultError):
            vault.data

    def test_create_refuses_existing(self) -> None:
        self._new_vault()
        with self.assertRaises(VaultError):
            Vault(self.path).create("other")

    def test_unlock_missing_file(self) -> None:
        with self.assertRaises(VaultError):
            Vault(self.path / "missing.json").unlock("x")

    def test_tampered_ciphertext_detected(self) -> None:
        self._new_vault()
        import base64
        import json

        envelope = json.loads(self.path.read_text(encoding="utf-8"))
        raw = bytearray(base64.b64decode(envelope["ciphertext"]))
        raw[0] ^= 0xFF
        envelope["ciphertext"] = base64.b64encode(bytes(raw)).decode("ascii")
        self.path.write_text(json.dumps(envelope), encoding="utf-8")
        vault = Vault(self.path)
        with self.assertRaises(VaultError):
            vault.unlock("hunter2!")


@unittest.skipUnless(HAS_CRYPTO, "cryptography package not installed")
class RotationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.vault = Vault(Path(self._tmp.name) / "r.vault.json")
        self.vault.create("pw")
        self.now = datetime.now(timezone.utc)

    def _entry(self, rotate_days: int = 90, age_days: int | None = 10):
        entry = self.vault.add_secret(
            "", None, name="k", secret="v", rotate_days=rotate_days
        )
        if age_days is not None:
            entry.last_rotated = (self.now - timedelta(days=age_days)).isoformat()
            self.vault.save()
        return entry

    def test_status_buckets(self) -> None:
        self.assertEqual(rotation_status(self._entry(age_days=10)), "ok")
        self.assertEqual(rotation_status(self._entry(age_days=80)), "due-soon")
        self.assertEqual(rotation_status(self._entry(age_days=95)), "overdue")
        self.assertEqual(rotation_status(self._entry(rotate_days=0)), "off")

        fresh = self.vault.add_secret("", None, name="novalue", rotate_days=30)
        fresh.last_rotated = ""
        self.assertEqual(rotation_status(fresh), "never")

    def test_add_stamps_last_rotated_only_with_value(self) -> None:
        with_value = self.vault.add_secret("", None, name="a", secret="x")
        self.assertTrue(with_value.last_rotated)
        without = self.vault.add_secret("", None, name="b", secret="")
        self.assertEqual(without.last_rotated, "")

    def test_setting_new_value_rotates(self) -> None:
        entry = self._entry(age_days=95)
        self.assertEqual(rotation_status(entry), "overdue")
        old_stamp = entry.last_rotated
        self.vault.update_secret("", None, entry.id, secret="new-value")
        self.assertNotEqual(entry.last_rotated, old_stamp)
        self.assertEqual(rotation_status(entry), "ok")

    def test_mark_rotated_without_value_change(self) -> None:
        entry = self._entry(age_days=95)
        self.vault.mark_rotated("", None, entry.id)
        self.assertEqual(rotation_status(entry), "ok")
        self.assertEqual(entry.secret.decode(), "v")  # value untouched

    def test_report_groups_by_status_and_location(self) -> None:
        client = self.vault.add_client("Hooli")
        project = self.vault.add_project(client.id, "Nucleus")
        self._entry(age_days=95)  # unfiled, overdue
        overdue_p = self.vault.add_secret(
            client.id, project.id, name="pk", secret="v", rotate_days=30
        )
        overdue_p.last_rotated = (self.now - timedelta(days=40)).isoformat()
        self.vault.save()
        off = self.vault.add_secret(client.id, None, name="ck", secret="v")

        report = rotation_report(self.vault.data)
        self.assertIn("unfiled", [i["where"] for i in report["overdue"]])
        self.assertIn(
            "Hooli/Nucleus", [i["where"] for i in report["overdue"]]
        )
        self.assertIn(off.id, [i["id"] for i in report["off"]])

    def test_old_vault_files_without_rotation_fields_load(self) -> None:
        entry = self._entry()
        raw = entry.to_dict()
        del raw["rotate_days"], raw["last_rotated"]
        rebuilt = type(entry).from_dict(raw)
        self.assertEqual(rebuilt.rotate_days, 0)
        self.assertEqual(rebuilt.last_rotated, "")


@unittest.skipUnless(HAS_CRYPTO, "cryptography package not installed")
class ProjectScanConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.vault = Vault(Path(self._tmp.name) / "s.vault.json")
        self.vault.create("pw")
        self.client = self.vault.add_client("Acme")
        self.project = self.vault.add_project(self.client.id, "Core API")

    def test_set_scan_config_roundtrip(self) -> None:
        self.vault.set_project_scan_config(
            self.client.id, self.project.id, "github", "acme-org"
        )
        again = Vault(self.vault.path)
        again.unlock("pw")
        loaded = again.get_project(self.client.id, self.project.id)
        self.assertEqual(loaded.connector, "github")
        self.assertEqual(loaded.target, "acme-org")
        self.assertIsNone(loaded.last_scan)

    def test_set_scan_config_rejects_unknown_connector(self) -> None:
        with self.assertRaises(VaultError):
            self.vault.set_project_scan_config(
                self.client.id, self.project.id, "ftp", "host"
            )

    def test_record_scan_result_roundtrip(self) -> None:
        self.vault.set_project_scan_config(
            self.client.id, self.project.id, "demo", "demo-org"
        )
        scan = ScanRecord(
            at="2026-09-29T12:00:00+00:00",
            connector="demo",
            target="demo-org",
            cmm_level=2,
            cmm_name="Managed",
            score=41.2,
            debt_points=95,
            summary="CMM L2 Managed (41.2/100)",
        )
        self.vault.record_scan_result(self.client.id, self.project.id, scan)
        again = Vault(self.vault.path)
        again.unlock("pw")
        loaded = again.get_project(self.client.id, self.project.id)
        assert loaded.last_scan is not None
        self.assertEqual(loaded.last_scan.cmm_level, 2)
        self.assertEqual(loaded.last_scan.score, 41.2)
        self.assertIn("L2", loaded.last_scan.summary)

    def test_old_projects_without_scan_fields_load(self) -> None:
        raw = self.project.to_dict()
        del raw["connector"], raw["target"]
        rebuilt = Project.from_dict(raw)
        self.assertEqual(rebuilt.connector, "")
        self.assertEqual(rebuilt.target, "")
        self.assertIsNone(rebuilt.last_scan)


class TuiImportTests(unittest.TestCase):
    def test_tui_module_imports(self) -> None:
        try:
            import textual  # noqa: F401
        except ImportError:
            self.skipTest("textual not installed")
        from techdebtfixer import tui  # noqa: F401

        self.assertTrue(hasattr(tui, "VaultTui"))
        self.assertTrue(hasattr(tui, "run"))


if __name__ == "__main__":
    unittest.main()
