"""Command-line interface for techdebtfixer."""

from __future__ import annotations

import argparse
import sys

from techdebtfixer import __version__
from techdebtfixer.connectors import (
    ConnectorError,
    get_connector,
    registry,
)
from techdebtfixer.credentials import (
    CredentialsError,
    from_args,
    from_env,
    from_json,
    mask_secret,
)
from techdebtfixer.pipeline import run_assessment
from techdebtfixer.report import render_json, render_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="techdebtfixer",
        description=(
            "Log in to a client's environment with their credentials, review "
            "security posture and technical debt, place the org on the Common "
            "Maturity Model, and produce a remediation roadmap. Includes an "
            "encrypted vault TUI for storing client credentials."
        ),
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument(
        "--tui",
        action="store_true",
        help="launch the interactive credential-vault TUI",
    )
    parser.add_argument(
        "--vault-file",
        default=None,
        metavar="PATH",
        help="vault file path for --tui (default: ~/.techdebtfixer/vault.vault.json)",
    )

    parser.add_argument(
        "--connector",
        "-c",
        choices=sorted(registry),
        default=None,
        help="connector to use (default: demo)",
    )
    parser.add_argument(
        "--target",
        "-t",
        default="",
        help="target identifier: org name (github), hostname (web) or path (local)",
    )

    creds = parser.add_argument_group("credentials")
    creds.add_argument("--token", "-T", default=None, help="API token / PAT")
    creds.add_argument("--username", "-u", default=None, help="username")
    creds.add_argument("--password", "-p", default=None, help="password (prefer env/file)")
    creds.add_argument(
        "--ask-password",
        action="store_true",
        help="prompt for the password interactively",
    )
    creds.add_argument("--domain", default=None, help="domain / realm, if needed")
    creds.add_argument(
        "--creds-file",
        default=None,
        help="JSON file with credentials (takes precedence over flags)",
    )
    creds.add_argument(
        "--use-env",
        action="store_true",
        help="read credentials from TDF_TOKEN/TDF_USERNAME/TDF_PASSWORD/TDF_DOMAIN",
    )

    out = parser.add_argument_group("output")
    out.add_argument(
        "--format",
        "-f",
        choices=("text", "json"),
        default=None,
        help="report format (default: text)",
    )
    out.add_argument(
        "--output",
        "-o",
        default=None,
        help="also write the report to this file",
    )
    out.add_argument(
        "--list-connectors",
        action="store_true",
        help="list available connectors and exit",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Bare `techdebtfixer` (no assessment flags) opens the vault TUI.
    assessment_flags = any(
        (
            args.connector is not None,
            bool(args.target),
            args.token is not None,
            args.username is not None,
            args.password is not None,
            args.ask_password,
            args.domain is not None,
            args.creds_file is not None,
            args.use_env,
            args.format is not None,
            args.output is not None,
            args.list_connectors,
        )
    )
    if not assessment_flags:
        args.tui = True

    if args.tui:
        try:
            from techdebtfixer.tui import run as run_tui
        except ImportError:
            print(
                "error: the TUI needs 'textual' and 'cryptography'; "
                "install with: pip install 'techdebtfixer[tui]'",
                file=sys.stderr,
            )
            return 2
        return run_tui(vault_path=args.vault_file)

    if args.list_connectors:
        print("Available connectors:")
        for name in sorted(registry):
            print(f"  - {name}")
        return 0

    # --- resolve credentials (file > env > flags) ---
    try:
        if args.creds_file:
            creds = from_json(args.creds_file)
        elif args.use_env:
            creds = from_env()
        else:
            creds = from_args(
                token=args.token,
                username=args.username,
                password=args.password,
                domain=args.domain,
                ask_password=args.ask_password,
            )
    except CredentialsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # --- build and run the assessment ---
    try:
        connector_cls = get_connector(args.connector or "demo")
    except ConnectorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    target = args.target or creds.domain
    connector = connector_cls(creds, target)

    try:
        assessment = run_assessment(connector, creds)
    except ConnectorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    # --- emit the report ---
    fmt = args.format or "text"
    report = render_text(assessment) if fmt == "text" else render_json(assessment)
    print(report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
        print(f"report written to {args.output}", file=sys.stderr)

    # Non-zero exit when critical/high findings exist, so CI can gate on it.
    bad = any(
        f.severity in ("critical", "high") and f.status == "fail"
        for f in assessment.findings
    )
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
