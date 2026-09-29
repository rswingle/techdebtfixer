"""Web connector: TLS and HTTP security header checks over HTTPS.

Uses only the standard library (ssl + urllib). Credentials, if provided,
are sent as a Bearer token so authenticated pages can be checked too.
"""

from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from techdebtfixer.connectors.base import Connector, ConnectorError, register
from techdebtfixer.models import Finding

TIMEOUT = 15

# (header, severity, description of why it matters)
_SECURITY_HEADERS = [
    ("strict-transport-security", "high", "HSTS forces HTTPS for all visitors"),
    ("content-security-policy", "high", "CSP mitigates XSS and injection"),
    ("x-content-type-options", "medium", "prevents MIME-type sniffing"),
    ("x-frame-options", "medium", "clickjacking protection"),
    ("referrer-policy", "low", "limits referrer leakage"),
]


def _normalize_host(target: str) -> str:
    target = target.strip()
    if "://" in target:
        host = urllib.parse.urlsplit(target).hostname or ""
    else:
        host = target.split("/")[0]
    if not host:
        raise ConnectorError(f"could not parse a hostname from target '{target}'")
    return host


@register
class WebConnector(Connector):
    """Audit one HTTPS endpoint for transport and header hygiene."""

    name = "web"

    def validate(self) -> None:
        host = _normalize_host(self.target)
        self.target = host

    def gather(self) -> list[Finding]:
        host = self.target
        findings: list[Finding] = []

        # --- TLS certificate validity ---
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
            findings.append(
                Finding(
                    check_id="web.tls.valid",
                    title=f"Valid public TLS certificate for {host}",
                    category="security",
                    severity="high",
                    status="pass",
                    detail="certificate chain verified against system CAs",
                    weight=2.0,
                )
            )
            not_after = cert.get("notAfter")
            if not_after:
                expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                days_left = (expires - datetime.now(timezone.utc)).days
                if days_left < 14:
                    status, sev, det = "fail", "high", f"expires in {days_left} days"
                elif days_left < 30:
                    status, sev, det = "warn", "medium", f"expires in {days_left} days"
                else:
                    status, sev, det = "pass", "info", f"expires in {days_left} days"
                findings.append(
                    Finding(
                        check_id="web.tls.expiry",
                        title=f"TLS certificate renewal runway for {host}",
                        category="security",
                        severity=sev,
                        status=status,
                        detail=det,
                        remediation="Ensure automated certificate renewal (e.g. ACME).",
                        weight=1.5,
                    )
                )
        except (ssl.SSLError, OSError) as exc:
            findings.append(
                Finding(
                    check_id="web.tls.valid",
                    title=f"TLS connection to {host}",
                    category="security",
                    severity="critical",
                    status="fail",
                    detail=f"could not establish a verified TLS session: {exc}",
                    remediation="Serve the site over HTTPS with a valid certificate.",
                    weight=2.0,
                )
            )

        # --- HTTP response headers ---
        url = f"https://{host}/"
        req = urllib.request.Request(url, method="GET")
        token = self.creds.token
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        req.add_header("User-Agent", "techdebtfixer")
        headers: dict[str, str] = {}
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
            http_ok = True
            status_line = "reachable"
        except urllib.error.HTTPError as exc:
            headers = {k.lower(): v for k, v in exc.headers.items()}
            http_ok = True
            status_line = f"HTTP {exc.code} (checked response headers anyway)"
        except urllib.error.URLError as exc:
            http_ok = False
            status_line = f"unreachable: {exc.reason}"

        if not http_ok:
            findings.append(
                Finding(
                    check_id="web.reachability",
                    title=f"HTTP endpoint reachable at {url}",
                    category="security",
                    severity="high",
                    status="fail",
                    detail=status_line,
                    remediation="Ensure the site is served and reachable.",
                    weight=1.5,
                )
            )
        else:
            missing: list[str] = []
            for header, severity, why in _SECURITY_HEADERS:
                present = header in headers
                if not present:
                    missing.append(header)
                findings.append(
                    Finding(
                        check_id=f"web.header.{header}",
                        title=f"Security header '{header}' on {host}",
                        category="security",
                        severity=severity,
                        status="pass" if present else "fail",
                        detail=headers.get(header, f"missing - {why}"),
                        remediation=f"Send the {header} header on all responses.",
                        weight=1.0 if severity in ("high", "medium") else 0.5,
                    )
                )
            findings.append(
                Finding(
                    check_id="web.reachability",
                    title=f"HTTP endpoint reachable at {url}",
                    category="security",
                    severity="info",
                    status="pass",
                    detail=status_line,
                    weight=0.5,
                )
            )
        return findings
