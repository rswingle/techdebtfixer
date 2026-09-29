"""Connectors for techdebtfixer.

Importing this package registers all built-in connectors. Third-party
connectors can subclass Connector and apply the same @register decorator.
"""

from techdebtfixer.connectors.base import (  # noqa: F401
    Connector,
    ConnectorError,
    get_connector,
    register,
    registry,
)

# Importing these modules triggers their @register side effects.
from techdebtfixer.connectors import demo  # noqa: F401,E402
from techdebtfixer.connectors import github  # noqa: F401,E402
from techdebtfixer.connectors import local  # noqa: F401,E402
from techdebtfixer.connectors import web  # noqa: F401,E402
