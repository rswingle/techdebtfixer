"""GitHub connector: audits an org's repositories using a PAT.

Uses the GitHub REST API with only the standard library (urllib), so the
tool has zero external dependencies.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone

from techdebtfixer.connectors.base import Connector, ConnectorError, register
from techdebtfixer.models import Finding

API_ROOT = "https://api.github.com"


def _request(url: str, token: str, timeout: int = 20) -> dict:
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "techdebtfixer",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        err = ConnectorError(f"GitHub API returned HTTP {exc.code} for {url}")
        err.status_code = exc.code  # type: ignore[attr-defined]
        raise err from exc
    except urllib.error.URLError as exc:
        raise ConnectorError(f"cannot reach GitHub: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise ConnectorError(f"non-JSON response from {url}") from exc


def _try_request(url: str, token: str) -> tuple[bool, dict | None, int | None]:
    """Request that never raises: returns (ok, payload, http_code)."""
    try:
        return True, _request(url, token), None
    except ConnectorError as exc:
        return False, None, getattr(exc, "status_code", None)


def _security_check(
    check_id: str,
    title: str,
    ok: bool,
    severity: str,
    detail: str,
    remediation: str,
    weight: float,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        category="security",
        severity=severity,
        status="pass" if ok else "fail",
        detail=detail,
        remediation=remediation,
        weight=weight,
    )


@register
class GitHubConnector(Connector):
    """Audit a GitHub organization's repositories."""

    name = "github"

    def validate(self) -> None:
        if not self.creds.token:
            raise ConnectorError(
                "github connector requires a token (PAT). Supply via --token, "
                "the TDF_TOKEN env var, or a JSON credentials file."
            )
        if not self.target:
            raise ConnectorError(
                "github connector requires a target org. Use --target <org>."
            )

    def gather(self) -> list[Finding]:
        findings: list[Finding] = []
        org = self.target
        token = self.creds.token

        try:
            repos = _request(f"{API_ROOT}/orgs/{org}/repos?per_page=100", token)
        except ConnectorError as exc:
            raise ConnectorError(
                f"cannot list repos for org '{org}': {exc}"
            ) from exc
        if not isinstance(repos, list):
            raise ConnectorError(f"unexpected response listing repos for '{org}'")

        findings.append(
            Finding(
                check_id="github.auth",
                title=f"Authenticated access to org '{org}'",
                category="security",
                severity="info",
                status="pass",
                detail=f"retrieved {len(repos)} repositories",
                weight=1.0,
            )
        )

        for repo in repos:
            name = repo.get("name", "?")
            full = f"{org}/{name}"

            # 1. Branch protection on the default branch
            default_branch = repo.get("default_branch", "main")
            ok, _payload, code = _try_request(
                f"{API_ROOT}/repos/{org}/{name}/branches/{default_branch}/protection",
                token,
            )
            if ok:
                bp_status, bp_detail = "pass", f"'{default_branch}' is protected"
            elif code == 404:
                bp_status = "fail"
                bp_detail = f"'{default_branch}' has no protection rules"
            elif code == 403:
                bp_status = "unknown"
                bp_detail = "token lacks permission to read branch protection"
            else:
                bp_status = "unknown"
                bp_detail = f"could not determine protection (HTTP {code})"
            findings.append(
                Finding(
                    check_id=f"github.branch-protection.{name}",
                    title=f"Branch protection on {full}",
                    category="security",
                    severity="high",
                    status=bp_status,
                    detail=bp_detail,
                    remediation=(
                        "Enable branch protection / rulesets on the default branch."
                    ),
                    weight=2.0,
                )
            )

            # 2. Issue backlog as a debt signal (count includes PRs)
            open_issues = repo.get("open_issues_count", 0)
            if open_issues > 200:
                bl_status, bl_sev = "fail", "medium"
            elif open_issues > 50:
                bl_status, bl_sev = "warn", "low"
            else:
                bl_status, bl_sev = "pass", "info"
            findings.append(
                Finding(
                    check_id=f"github.issue-backlog.{name}",
                    title=f"Issue backlog on {full}",
                    category="debt",
                    severity=bl_sev,
                    status=bl_status,
                    detail=f"{open_issues} open issues/PRs",
                    remediation="Triage the backlog; close or schedule stale issues.",
                    weight=1.5,
                )
            )

            # 3. License present
            has_license = repo.get("license") is not None
            findings.append(
                Finding(
                    check_id=f"github.license.{name}",
                    title=f"License defined for {full}",
                    category="debt",
                    severity="low",
                    status="pass" if has_license else "warn",
                    detail="LICENSE detected" if has_license else "no LICENSE file",
                    remediation="Add a LICENSE file so usage terms are explicit.",
                    weight=0.5,
                )
            )

            # 4. Stale, unarchived repository
            pushed_at = repo.get("pushed_at", "")
            if pushed_at and not repo.get("archived", False):
                try:
                    pushed = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
                    age_days = (datetime.now(timezone.utc) - pushed).days
                except ValueError:
                    age_days = 0
                if age_days > 180:
                    findings.append(
                        Finding(
                            check_id=f"github.stale-repo.{name}",
                            title=f"Stale repository {full}",
                            category="debt",
                            severity="low",
                            status="warn",
                            detail=f"last push {age_days} days ago; consider archiving",
                            remediation=(
                                "Archive unused repositories to reduce attack "
                                "surface and noise."
                            ),
                            weight=0.5,
                        )
                    )
        return findings
