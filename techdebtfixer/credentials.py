"""Credential handling: parsing, validation and safe display.

Credentials are supplied by the client (CLI flags, env vars, or a JSON file)
and are never logged in plaintext.
"""

from __future__ import annotations

import getpass
import json
import os
from dataclasses import dataclass, field
from typing import Any


class CredentialsError(ValueError):
    """Raised when supplied credentials are incomplete or malformed."""


@dataclass
class Credentials:
    """Client-provided credentials for reaching the target network."""

    username: str = ""
    password: str = ""
    token: str = ""
    domain: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def kind(self) -> str:
        if self.token:
            return "token"
        if self.username and self.password:
            return "password"
        return "anonymous"

    def masked(self) -> str:
        parts = []
        if self.username:
            parts.append(f"username={self.username}")
        if self.token:
            parts.append(f"token={mask_secret(self.token)}")
        if self.password:
            parts.append(f"password={mask_secret(self.password)}")
        if self.domain:
            parts.append(f"domain={self.domain}")
        if self.extra:
            parts.append(f"extra_keys={sorted(self.extra)}")
        return ", ".join(parts) or "anonymous"


def mask_secret(secret: str, keep: int = 3) -> str:
    """Return e.g. 'ghp••••••••xyz' for safe display."""
    if not secret:
        return ""
    if len(secret) <= keep:
        return "•" * len(secret)
    return f"{secret[:keep]}{'•' * 8}{secret[-3:]}"


def from_args(
    token: str | None,
    username: str | None,
    password: str | None,
    domain: str | None,
    ask_password: bool,
) -> Credentials:
    """Assemble credentials from CLI args, optionally prompting for a password."""
    password = password or ""
    if ask_password and username and not password:
        password = getpass.getpass(f"Password for {username}: ")
    return Credentials(
        username=username or "",
        password=password,
        token=token or "",
        domain=domain or "",
    )


def from_env() -> Credentials:
    """Read credentials from well-known environment variables."""
    return Credentials(
        username=os.environ.get("TDF_USERNAME", ""),
        password=os.environ.get("TDF_PASSWORD", ""),
        token=os.environ.get("TDF_TOKEN", ""),
        domain=os.environ.get("TDF_DOMAIN", ""),
    )


def from_json(path: str) -> Credentials:
    """Load a JSON credentials file: {"username": ..., "token": ..., ...}."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError as exc:
        raise CredentialsError(f"credentials file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise CredentialsError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise CredentialsError(f"credentials file {path} must contain a JSON object")
    known = {"username", "password", "token", "domain"}
    extra = {k: v for k, v in data.items() if k not in known}
    creds = Credentials(
        username=str(data.get("username", "")),
        password=str(data.get("password", "")),
        token=str(data.get("token", "")),
        domain=str(data.get("domain", "")),
        extra=extra,
    )
    if creds.kind() == "anonymous":
        raise CredentialsError(
            f"no usable credentials in {path}: need 'token' or 'username'+'password'"
        )
    return creds
