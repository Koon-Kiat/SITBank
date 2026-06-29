# Repository Secret Scanning

SITBank uses two complementary repository controls:

- the custom repository secret scanner in
  `ops/security/scan_repository_secrets.py`, which remains in the main CI job
  and `scripts/ci-local` with Git-history scanning; and
- Gitleaks 8.30.1 in `.github/workflows/gitleaks.yml`, configured by
  `.gitleaks.toml`.

Gitleaks runs for pull requests to `main`, pushes to `main`, manual dispatches,
and a weekly scheduled full-history scan. The workflow checks out full Git
history without persisted credentials, downloads the pinned Linux CLI release,
verifies its SHA-256 checksum, and scans all refs with `--redact`. It requests
only `contents: read`, uses no production secrets or deployment credentials,
and runs no deployment, Cloudflare, Tailscale, database, or bootstrap command.

The scan covers application and test code, workflows, `ops`, `scripts`,
configuration, Docker and Compose files, Nginx configuration, documentation,
templates, fixtures, and full Git history. No path is excluded. The
`.gitleaks.toml` file extends the complete built-in ruleset and has no
baseline. Its reviewed allowlists cover only a public package checksum, a
synthetic historical password fixture, historical configuration-name mapping
rows, and historical private-key-header validation cases. Each exception is
constrained by rule, exact path, line shape, and—where historical—commit.

The workflow uploads no artifact and no SARIF. This is intentional: the
redacted job log supplies file, rule, commit, and line evidence without
creating a raw report that might retain detected values. Consequently the
workflow does not request `security-events: write`.

## Safe Failure Triage

Do not paste a finding, suspected credential, raw report, or affected file
contents into a public issue or pull-request comment. Use the redacted rule,
path, commit, and line metadata from the protected workflow log.

To reproduce with the same Gitleaks version after installing and verifying the
pinned release:

```bash
gitleaks git --config .gitleaks.toml --log-opts=--all --redact \
  --no-banner --no-color --verbose .
```

For a false positive:

1. Confirm privately that the matched value is synthetic, expired, or a
   clearly fake example and was never usable.
2. Prefer changing the example so it is unmistakably fake.
3. If an exception is still necessary, add a narrow allowlist matching only
   that confirmed fake/test value, document the rationale beside it, and add a
   focused policy test. Never exclude `.github/workflows`, `ops`, `scripts`,
   `config.py`, deployment files, or an entire documentation/test directory.

For a real secret in current content or full Git history:

1. Revoke the exposed credential and rotate it at its provider immediately.
2. Preserve private incident evidence and follow
   `docs/security/incident-response.md`.
3. Remove the value from current content, then assess a coordinated history
   rewrite. Removing it only from a later commit does not undo disclosure.
4. Review access and audit logs, invalidate dependent sessions or keys where
   applicable, and verify that the old credential no longer works.
5. Rerun both Gitleaks and the custom scanner. Never add the real value to an
   allowlist or baseline merely to make CI pass.

Example secrets must remain obviously fake. A baseline may be introduced only
in a separately reviewed change for confirmed historical false positives or
already-rotated findings, and it must not retain raw secret values.

After the workflow is stable, branch protection should require the
`Gitleaks / Full-history secret scan` check for `main`. Gitleaks complements
application redaction, secret-file handling, GitHub secret scanning if it is
separately enabled, dependency/SAST/DAST controls, and the custom scanner; it
does not replace any of them.
