"""Local connector: audits the local machine / repository in place.

Collects quick-hygiene signals without requiring network access:
secrets-looking files, dependency manifest staleness, test presence,
CI configuration and README/LICENSE presence.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from techdebtfixer.connectors.base import Connector, ConnectorError, register
from techdebtfixer.models import Finding

# Heuristic patterns for values that look like live credentials.
_SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private key block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("generic api key assignment", re.compile(r"(?i)(api[_-]?key|secret)\s*[:=]\s*['\"][A-Za-z0-9]{16,}['\"]")),
]

_SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "__pycache__",
    ".mypy_cache", ".pytest_cache", "dist", "build", ".tox", "site-packages",
}

_TEST_MARKERS = ("test_", "_test", "tests", "spec", "conftest")
_CI_MARKERS = (".github/workflows", ".gitlab-ci.yml", "Jenkinsfile", ".circleci", ".drone.yml")


def _iter_files(root: Path, limit: int = 5000):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            yield Path(dirpath) / fname
            count += 1
            if count >= limit:
                return


@register
class LocalConnector(Connector):
    """Audit a local directory (defaults to the current working directory)."""

    name = "local"

    def validate(self) -> None:
        root = Path(self.target or ".").resolve()
        if not root.exists():
            raise ConnectorError(f"target path does not exist: {root}")
        if not root.is_dir():
            raise ConnectorError(f"target path is not a directory: {root}")
        self.target = str(root)

    def gather(self) -> list[Finding]:
        root = Path(self.target)
        findings: list[Finding] = []

        file_count = 0
        secret_hits: list[str] = []
        manifests: set[str] = set()
        has_tests = False
        has_ci = False
        has_readme = False
        has_license = False
        lock_files: set[str] = set()

        for path in _iter_files(root):
            rel = str(path.relative_to(root))
            file_count += 1
            name = path.name.lower()
            rel_posix = path.relative_to(root).as_posix().lower()

            if name == "readme.md" or name.startswith("readme"):
                has_readme = True
            if name == "license":
                has_license = True
            if name in ("package-lock.json", "poetry.lock", "uv.lock",
                        "yarn.lock", "pipfile.lock", "go.sum"):
                lock_files.add(name)
            if name in ("package.json", "requirements.txt", "pyproject.toml",
                        "go.mod", "gemfile", "pom.xml", "cargo.toml"):
                manifests.add(name)
            if any(m in rel_posix for m in _TEST_MARKERS) and name.endswith(
                (".py", ".ts", ".js", ".go", ".rs", ".rb", ".java")
            ):
                has_tests = True
            if any(m in rel_posix for m in _CI_MARKERS):
                has_ci = True

            # Only scan small text-ish files for secrets.
            try:
                if path.stat().st_size <= 256_000:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                    for label, pattern in _SECRET_PATTERNS:
                        if pattern.search(text):
                            secret_hits.append(f"{rel}: {label}")
            except OSError:
                continue

        if secret_hits:
            sample = "; ".join(secret_hits[:5])
            more = f" (+{len(secret_hits) - 5} more)" if len(secret_hits) > 5 else ""
            findings.append(
                Finding(
                    check_id="local.secrets",
                    title="Possible secrets committed in files",
                    category="security",
                    severity="critical",
                    status="fail",
                    detail=f"{len(secret_hits)} potential secrets: {sample}{more}",
                    remediation=(
                        "Revoke and rotate the exposed credentials, remove them "
                        "from history, and add secret scanning + .gitignore rules."
                    ),
                    weight=3.0,
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="local.secrets",
                    title="No obvious secrets in scanned files",
                    category="security",
                    severity="info",
                    status="pass",
                    detail=f"scanned {file_count} files",
                    weight=1.0,
                )
            )

        findings.append(
            Finding(
                check_id="local.tests",
                title="Automated tests present",
                category="debt",
                severity="high",
                status="pass" if has_tests else "fail",
                detail="test files detected" if has_tests else "no test files found",
                remediation="Add a test suite and run it in CI.",
                weight=2.0,
            )
        )

        findings.append(
            Finding(
                check_id="local.ci",
                title="CI configuration present",
                category="security",
                severity="medium",
                status="pass" if has_ci else "fail",
                detail="CI config detected" if has_ci else "no CI configuration found",
                remediation=(
                    "Add a CI pipeline that runs tests, linters and dependency "
                    "audits on every change."
                ),
                weight=1.5,
            )
        )

        findings.append(
            Finding(
                check_id="local.lockfiles",
                title="Dependency lockfiles committed",
                category="debt",
                severity="medium",
                status="pass" if lock_files else ("fail" if manifests else "unknown"),
                detail=(
                    f"locks: {sorted(lock_files)}"
                    if lock_files
                    else (
                        f"manifests without locks: {sorted(manifests)}"
                        if manifests
                        else "no dependency manifests found"
                    )
                ),
                remediation="Commit lockfiles so builds are reproducible.",
                weight=1.5,
            )
        )

        findings.append(
            Finding(
                check_id="local.docs",
                title="README and LICENSE present",
                category="debt",
                severity="low",
                status="pass" if (has_readme and has_license)
                else ("warn" if has_readme or has_license else "fail"),
                detail=f"readme={has_readme} license={has_license}",
                remediation="Add a README describing setup and a LICENSE file.",
                weight=0.5,
            )
        )

        return findings
