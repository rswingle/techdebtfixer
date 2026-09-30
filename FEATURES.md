# FEATURES

Implemented in this prototype (Python ≥3.10, stdlib only, zero dependencies):

- **Credential handling**: PAT/token, username+password (with interactive
  prompt), JSON credentials file, or env vars; precedence file > env > flags;
  secrets masked in all output.
- **Pluggable connector registry**: `demo`, `github` (REST via urllib),
  `local` (filesystem hygiene), `web` (TLS + security headers). New targets
  plug in via one `Connector` subclass + `@register`.
- **Assessment pipeline**: connector findings → weighted posture score →
  debt points → CMM level → phased roadmap → text/JSON report.
- **Common Maturity Model**: 5 levels (Initial → Optimizing) with score
  thresholds; report shows current level, next level and the debt-point gap.
- **Technical-debt register**: failing findings become debt items with
  severity-based point values (critical 40 / high 20 / medium 10 / low 5).
- **Remediation roadmap**: ordered steps grouped into 4 phases, each with
  effort sizing, impact statement and affected check IDs; steps that clear
  the debt gap to the next CMM level are flagged as level-unlocking.
- **Reporting**: human-readable text or machine-readable JSON, optional
  `--output` file, CI-friendly exit codes (0 clean, 1 critical/high fails,
  2 credentials/args error, 3 connector error).
- **Encrypted credential vault** — optional TUI (`--tui`) storing clients,
  projects and secrets in one AES-256-GCM encrypted file; PBKDF2-HMAC-SHA256
  (600k iterations) derives the key from a master password; file written with
  mode 0600 via atomic replace; wrong passwords leave the vault locked.
- **Rotation reminders** — per-secret rotation policies with overdue /
  due-soon flags in the tree and vault summary; `r` marks a secret rotated
  and saving a new value auto-stamps the rotation date.
- **Assessments from the TUI** — projects carry a scan target (connector +
  target id); `a` runs the full assessment pipeline in a background thread
  and records CMM level, score and debt points on the project; connector
  tokens are pulled from the project's encrypted secrets.
- **Scan history and trends** — every assessment is appended to the
  project's encrypted history (50 kept); `h` lists all scans with per-scan
  trend arrows, and the detail pane shows the delta versus the previous run.
- **CI** — GitHub Actions runs the suite on Linux and macOS across Python
  3.10/3.12/3.14 plus CLI smoke checks.
- **Tests**: 53 stdlib `unittest` tests covering scoring, credentials,
  roadmap ordering, registry, a full demo end-to-end run, the vault and
  headless TUI flows.
