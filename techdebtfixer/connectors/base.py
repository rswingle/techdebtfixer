"""Connector base class and registry.

A connector knows how to authenticate to a target environment with
client-provided credentials and gather findings from it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from techdebtfixer.credentials import Credentials
from techdebtfixer.models import Assessment

if TYPE_CHECKING:
    from techdebtfixer.models import Finding


class ConnectorError(RuntimeError):
    """Raised when a connector cannot reach or authenticate to the target."""


class Connector(ABC):
    """Base class for target-environment connectors."""

    name: str = "base"

    def __init__(self, creds: Credentials, target: str) -> None:
        self.creds = creds
        self.target = target

    @abstractmethod
    def validate(self) -> None:
        """Raise ConnectorError if credentials/target are unusable."""

    @abstractmethod
    def gather(self) -> list["Finding"]:
        """Collect findings from the target environment."""

    def build_assessment(self, findings: list["Finding"]) -> Assessment:
        return Assessment(target=self.target, connector=self.name, findings=findings)


registry: dict[str, type[Connector]] = {}


def register(cls: type[Connector]) -> type[Connector]:
    """Class decorator: add a Connector subclass to the registry."""
    registry[cls.name] = cls
    return cls


def get_connector(name: str) -> type[Connector]:
    """Look up a connector class by name, listing options when unknown."""
    if name not in registry:
        known = ", ".join(sorted(registry)) or "(none registered)"
        raise ConnectorError(f"unknown connector '{name}'. Known: {known}")
    return registry[name]
