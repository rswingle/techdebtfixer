# TODO

- [ ] Vault TUI: optional OS-keychain backend; posture chart in the
  history view (score over time); scheduled re-scan reminders.
- [ ] GitHub connector: paginate beyond 100 repos; also check dependabot.yml,
  code scanning alerts and Actions workflow permissions.
- [ ] Web connector: follow redirects and score cookie flags; check multiple
  paths, not just `/`.
- [ ] Local connector: honor `.gitignore`; estimate dependency staleness from
  manifest/lock dates.
- [ ] Add an `sso`/`ldap` connector example for corporate-network logins
  (username/password + domain already plumbed through Credentials).
- [ ] Configurable severity/weight table via a TOML/JSON policy file.
- [ ] Baseline diffing: compare two saved JSON reports and show the debt
  trend over time (feeds CMM Level 4 "measured" practices).
- [ ] `--fail-on` flag to tune the CI exit-code gate (e.g. warn-only).
