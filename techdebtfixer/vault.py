"""Encrypted credential vault for multiple clients.

Secrets are stored in a single file encrypted with AES-256-GCM. The
encryption key is derived from a master password with PBKDF2-HMAC-SHA256.
The file never contains plaintext secrets or the derived key.

Requires the optional `cryptography` package (install with the `tui` extra).
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    _CRYPTO_IMPORT_ERROR: ImportError | None = None
except ImportError as exc:  # pragma: no cover - exercised only without extras
    _CRYPTO_IMPORT_ERROR = exc

FORMAT_VERSION = 1
PBKDF2_ITERATIONS = 600_000
VAULT_SUFFIX = ".vault.json"


class VaultError(RuntimeError):
    """Raised for vault file, password or lookup problems."""


def default_vault_path() -> Path:
    return Path.home() / ".techdebtfixer" / ("vault" + VAULT_SUFFIX)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


@dataclass
class SecretEntry:
    """One stored credential or key."""

    id: str
    name: str
    kind: str = "api-key"
    username: str = ""
    notes: str = ""
    rotate_days: int = 0  # rotation policy in days; 0 = tracking disabled
    last_rotated: str = ""  # ISO timestamp of the last manual rotation
    secret: bytes = b""
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "username": self.username,
            "notes": self.notes,
            "rotate_days": self.rotate_days,
            "last_rotated": self.last_rotated,
            "secret_b64": base64_encode(self.secret),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecretEntry:
        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            kind=str(data.get("kind", "api-key")),
            username=str(data.get("username", "")),
            notes=str(data.get("notes", "")),
            rotate_days=int(data.get("rotate_days", 0)),
            last_rotated=str(data.get("last_rotated", "")),
            secret=base64_decode(data.get("secret_b64", "")),
            created_at=str(data.get("created_at", _now())),
            updated_at=str(data.get("updated_at", _now())),
        )


@dataclass
class ScanRecord:
    """Result of the last assessment run against a project target."""

    at: str
    connector: str
    target: str
    cmm_level: int
    cmm_name: str
    score: float
    debt_points: int
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "at": self.at,
            "connector": self.connector,
            "target": self.target,
            "cmm_level": self.cmm_level,
            "cmm_name": self.cmm_name,
            "score": self.score,
            "debt_points": self.debt_points,
            "summary": self.summary,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanRecord:
        return cls(
            at=str(data.get("at", "")),
            connector=str(data.get("connector", "")),
            target=str(data.get("target", "")),
            cmm_level=int(data.get("cmm_level", 0)),
            cmm_name=str(data.get("cmm_name", "")),
            score=float(data.get("score", 0.0)),
            debt_points=int(data.get("debt_points", 0)),
            summary=str(data.get("summary", "")),
        )


# Maximum scan records kept per project (oldest dropped).
SCAN_HISTORY_LIMIT = 50


def diff_scans(older: ScanRecord, newer: ScanRecord) -> dict[str, float]:
    """Trend between two scans; positive numbers are improvements.

    score_delta  : posture score change (e.g. +4.5)
    debt_delta   : debt points change, negated so a decrease is positive
    level_delta  : CMM level change (e.g. +1)
    """
    return {
        "score_delta": round(newer.score - older.score, 1),
        "debt_delta": older.debt_points - newer.debt_points,
        "level_delta": newer.cmm_level - older.cmm_level,
    }


@dataclass
class Project:
    """A client project: an assessment target plus its own secrets."""

    id: str
    name: str
    secrets: dict[str, SecretEntry] = field(default_factory=dict)
    connector: str = ""  # demo | github | local | web; empty = not configured
    target: str = ""  # org name, hostname, or filesystem path
    scan_history: list[ScanRecord] = field(default_factory=list)  # oldest first
    created_at: str = field(default_factory=_now)

    @property
    def last_scan(self) -> ScanRecord | None:
        return self.scan_history[-1] if self.scan_history else None

    def to_dict(self) -> dict[str, Any]:
        out = {
            "id": self.id,
            "name": self.name,
            "created_at": self.created_at,
            "connector": self.connector,
            "target": self.target,
            "scan_history": [s.to_dict() for s in self.scan_history],
            "secrets": {sid: s.to_dict() for sid, s in self.secrets.items()},
        }
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Project:
        history: list[ScanRecord] = [
            ScanRecord.from_dict(sd)
            for sd in data.get("scan_history", [])
            if isinstance(sd, dict)
        ]
        if not history:
            # Vault files written before scan history existed.
            legacy = data.get("last_scan")
            if isinstance(legacy, dict):
                history = [ScanRecord.from_dict(legacy)]
        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            created_at=str(data.get("created_at", _now())),
            connector=str(data.get("connector", "")),
            target=str(data.get("target", "")),
            scan_history=history,
            secrets={
                sid: SecretEntry.from_dict(sd)
                for sid, sd in data.get("secrets", {}).items()
            },
        )


@dataclass
class Client:
    """One client account: projects plus a client-wide secrets area."""

    id: str
    name: str
    projects: dict[str, Project] = field(default_factory=dict)
    secrets: dict[str, SecretEntry] = field(default_factory=dict)
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "created_at": self.created_at,
            "projects": {pid: p.to_dict() for pid, p in self.projects.items()},
            "secrets": {sid: s.to_dict() for sid, s in self.secrets.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Client:
        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            created_at=str(data.get("created_at", _now())),
            projects={
                pid: Project.from_dict(pd)
                for pid, pd in data.get("projects", {}).items()
            },
            secrets={
                sid: SecretEntry.from_dict(sd)
                for sid, sd in data.get("secrets", {}).items()
            },
        )


@dataclass
class VaultData:
    """Decrypted contents of a vault."""

    clients: dict[str, Client] = field(default_factory=dict)
    secrets: dict[str, SecretEntry] = field(default_factory=dict)  # unfiled
    updated_at: str = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "updated_at": self.updated_at,
            "clients": {cid: c.to_dict() for cid, c in self.clients.items()},
            "secrets": {sid: s.to_dict() for sid, s in self.secrets.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VaultData:
        return cls(
            clients={
                cid: Client.from_dict(cd)
                for cid, cd in data.get("clients", {}).items()
            },
            secrets={
                sid: SecretEntry.from_dict(sd)
                for sid, sd in data.get("secrets", {}).items()
            },
            updated_at=str(data.get("updated_at", _now())),
        )


def base64_encode(raw: bytes) -> str:
    import base64

    return base64.b64encode(raw).decode("ascii")


def base64_decode(text: str) -> bytes:
    import base64

    return base64.b64decode(text.encode("ascii"))


# Days before the due date at which a secret counts as "due soon".
ROTATION_WARN_DAYS = 14


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


def rotation_status(entry: SecretEntry, now: datetime | None = None) -> str:
    """Classify a secret's rotation health.

    Returns one of:
      "off"        - no rotation policy set (rotate_days == 0)
      "never"      - policy set but the secret value was never set/rotated
      "overdue"    - past the due date
      "due-soon"   - within ROTATION_WARN_DAYS of the due date
      "ok"         - inside the rotation window
    """
    if entry.rotate_days <= 0:
        return "off"
    if not entry.last_rotated:
        return "never"
    now = now or datetime.now(timezone.utc)
    rotated = _parse_iso(entry.last_rotated)
    if rotated.tzinfo is None:
        rotated = rotated.replace(tzinfo=timezone.utc)
    age_days = (now - rotated).days
    if age_days >= entry.rotate_days:
        return "overdue"
    if age_days >= entry.rotate_days - ROTATION_WARN_DAYS:
        return "due-soon"
    return "ok"


def rotation_report(data: VaultData) -> dict[str, list[dict[str, str]]]:
    """Group all secrets by rotation status across the whole vault."""
    buckets: dict[str, list[dict[str, str]]] = {
        "overdue": [], "due-soon": [], "never": [], "ok": [], "off": [],
    }

    def record(where: str, entry: SecretEntry) -> None:
        buckets[rotation_status(entry)].append(
            {"where": where, "name": entry.name, "id": entry.id}
        )

    for entry in data.secrets.values():
        record("unfiled", entry)
    for client in data.clients.values():
        for entry in client.secrets.values():
            record(client.name, entry)
        for project in client.projects.values():
            for entry in project.secrets.values():
                record(f"{client.name}/{project.name}", entry)
    return buckets


class Vault:
    """File-backed encrypted vault. Unlock with the master password."""

    def __init__(self, path: str | Path | None = None) -> None:
        if _CRYPTO_IMPORT_ERROR is not None:
            raise VaultError(
                "vault support requires the 'cryptography' package; "
                "install with: pip install 'techdebtfixer[tui]'"
            ) from _CRYPTO_IMPORT_ERROR
        self.path = Path(path).expanduser() if path else default_vault_path()
        self._key: bytes | None = None
        self._kdf: dict[str, Any] | None = None
        self._data: VaultData | None = None

    # --- lifecycle -------------------------------------------------

    @property
    def exists(self) -> bool:
        return self.path.exists()

    @property
    def unlocked(self) -> bool:
        return self._data is not None

    @property
    def data(self) -> VaultData:
        if self._data is None:
            raise VaultError("vault is locked; unlock it first")
        return self._data

    def create(self, password: str) -> None:
        """Initialize a new vault file with an empty dataset."""
        if not password:
            raise VaultError("master password must not be empty")
        if self.exists:
            raise VaultError(f"vault already exists: {self.path}")
        self._kdf = {
            "algorithm": "PBKDF2-HMAC-SHA256",
            "iterations": PBKDF2_ITERATIONS,
            "salt": base64_encode(os.urandom(32)),
        }
        self._data = VaultData()
        self._key = self._derive_key(password)
        self.save()

    def unlock(self, password: str) -> None:
        """Decrypt the vault file. Raises VaultError on a wrong password."""
        if not self.exists:
            raise VaultError(f"no vault file at {self.path}")
        try:
            envelope = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise VaultError(f"cannot read vault file: {exc}") from exc
        try:
            self._kdf = envelope["kdf"]
            nonce = base64_decode(envelope["nonce"])
            ciphertext = base64_decode(envelope["ciphertext"])
        except (KeyError, TypeError, ValueError) as exc:
            raise VaultError(f"malformed vault file: {exc}") from exc
        key = self._derive_key(password)
        try:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
        except InvalidTag as exc:
            raise VaultError("wrong master password or corrupted vault") from exc
        try:
            self._data = VaultData.from_dict(json.loads(plaintext.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError) as exc:
            raise VaultError(f"corrupted vault payload: {exc}") from exc
        self._key = key

    def lock(self) -> None:
        self._key = None
        self._kdf = None
        self._data = None

    def save(self) -> None:
        """Re-encrypt and atomically replace the vault file."""
        if self._data is None or self._key is None or self._kdf is None:
            raise VaultError("vault is locked; nothing to save")
        nonce = os.urandom(12)
        ciphertext = AESGCM(self._key).encrypt(
            nonce, json.dumps(self._data.to_dict()).encode("utf-8"), None
        )
        envelope = {
            "version": FORMAT_VERSION,
            "kdf": self._kdf,
            "cipher": "AES-256-GCM",
            "nonce": base64_encode(nonce),
            "ciphertext": base64_encode(ciphertext),
            "updated_at": _now(),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:  # pragma: no cover - best effort on platforms w/o chmod
            pass

    def _derive_key(self, password: str) -> bytes:
        assert self._kdf is not None
        salt = base64_decode(self._kdf["salt"])
        iterations = int(self._kdf["iterations"])
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations
        )
        return kdf.derive(password.encode("utf-8"))

    # --- lookups ---------------------------------------------------

    def get_client(self, client_id: str) -> Client:
        try:
            return self.data.clients[client_id]
        except KeyError:
            raise VaultError(f"no such client: {client_id}") from None

    def get_project(self, client_id: str, project_id: str) -> Project:
        client = self.get_client(client_id)
        try:
            return client.projects[project_id]
        except KeyError:
            raise VaultError(f"no such project: {project_id}") from None

    def get_secret(
        self, client_id: str, project_id: str | None, secret_id: str
    ) -> SecretEntry:
        """Fetch one secret. Empty client_id means the unfiled area."""
        if not client_id:
            container = self.data.secrets
        elif project_id:
            container = self.get_project(client_id, project_id).secrets
        else:
            container = self.get_client(client_id).secrets
        try:
            return container[secret_id]
        except KeyError:
            raise VaultError(f"no such secret: {secret_id}") from None

    # --- mutations (each persists immediately) ----------------------

    def add_client(self, name: str) -> Client:
        name = name.strip()
        if not name:
            raise VaultError("client name must not be empty")
        client = Client(id=_new_id("c"), name=name)
        self.data.clients[client.id] = client
        self.save()
        return client

    def rename_client(self, client_id: str, name: str) -> None:
        self.get_client(client_id).name = name.strip()
        self.save()

    def delete_client(self, client_id: str) -> None:
        del self.data.clients[client_id]
        self.save()

    def add_project(self, client_id: str, name: str) -> Project:
        name = name.strip()
        if not name:
            raise VaultError("project name must not be empty")
        project = Project(id=_new_id("p"), name=name)
        self.get_client(client_id).projects[project.id] = project
        self.save()
        return project

    def rename_project(self, client_id: str, project_id: str, name: str) -> None:
        self.get_project(client_id, project_id).name = name.strip()
        self.save()

    def set_project_scan_config(
        self, client_id: str, project_id: str, connector: str, target: str
    ) -> None:
        """Attach an assessment target (connector + target id) to a project."""
        if connector not in {"demo", "github", "local", "web"}:
            raise VaultError(f"unknown connector: {connector}")
        project = self.get_project(client_id, project_id)
        project.connector = connector
        project.target = target.strip()
        self.save()

    def record_scan_result(
        self, client_id: str, project_id: str, scan: ScanRecord
    ) -> None:
        """Append a completed assessment to the project's scan history."""
        project = self.get_project(client_id, project_id)
        project.scan_history.append(scan)
        if len(project.scan_history) > SCAN_HISTORY_LIMIT:
            del project.scan_history[
                : len(project.scan_history) - SCAN_HISTORY_LIMIT
            ]
        self.save()

    def delete_project(self, client_id: str, project_id: str) -> None:
        del self.get_client(client_id).projects[project_id]
        self.save()

    def add_secret(
        self,
        client_id: str,
        project_id: str | None,
        name: str,
        kind: str = "api-key",
        username: str = "",
        secret: str = "",
        notes: str = "",
        rotate_days: int = 0,
    ) -> SecretEntry:
        name = name.strip()
        if not name:
            raise VaultError("secret name must not be empty")
        entry = SecretEntry(
            id=_new_id("s"),
            name=name,
            kind=(kind.strip() or "api-key"),
            username=username.strip(),
            notes=notes,
            rotate_days=max(0, int(rotate_days)),
            last_rotated=_now() if secret else "",
            secret=secret.encode("utf-8"),
        )
        if not client_id:
            self.data.secrets[entry.id] = entry
        elif project_id:
            self.get_project(client_id, project_id).secrets[entry.id] = entry
        else:
            self.get_client(client_id).secrets[entry.id] = entry
        self.save()
        return entry

    def update_secret(
        self,
        client_id: str,
        project_id: str | None,
        secret_id: str,
        *,
        name: str | None = None,
        kind: str | None = None,
        username: str | None = None,
        secret: str | None = None,
        notes: str | None = None,
        rotate_days: int | None = None,
    ) -> None:
        entry = self.get_secret(client_id, project_id, secret_id)
        if name is not None and name.strip():
            entry.name = name.strip()
        if kind is not None and kind.strip():
            entry.kind = kind.strip()
        if username is not None:
            entry.username = username.strip()
        if secret is not None and secret != "":
            entry.secret = secret.encode("utf-8")
            entry.last_rotated = _now()  # setting a new value rotates it
        if notes is not None:
            entry.notes = notes
        if rotate_days is not None:
            entry.rotate_days = max(0, int(rotate_days))
        entry.updated_at = _now()
        self.save()

    def delete_secret(
        self, client_id: str, project_id: str | None, secret_id: str
    ) -> None:
        if not client_id:
            del self.data.secrets[secret_id]
        elif project_id:
            del self.get_project(client_id, project_id).secrets[secret_id]
        else:
            del self.get_client(client_id).secrets[secret_id]
        self.save()

    def mark_rotated(
        self, client_id: str, project_id: str | None, secret_id: str
    ) -> SecretEntry:
        """Stamp the secret as rotated now (without changing its value)."""
        entry = self.get_secret(client_id, project_id, secret_id)
        entry.last_rotated = _now()
        entry.updated_at = _now()
        self.save()
        return entry
