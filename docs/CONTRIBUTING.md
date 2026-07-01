# Contributing

## Security Review

For security-sensitive changes, use
`docs/security/governance/security-governance.md` to identify the owner role, review
trigger, accepted-risk handling, and documentation updates. Closing a security
gap should update the gap register, framework matrix, threat model, design risk
register, and runbooks when their claims changed.

## Local CI

Run the repository's normal local checks with:

```bash
scripts/ci-local
```

Normal mode runs the Python, package, security, Git Bash syntax, and whitespace
checks. It discovers tracked shell scripts and Dockerfiles through
`ops/security/discover_lint_targets.py`. If ShellCheck, Hadolint, or Semgrep is
installed locally, normal mode runs it; otherwise it reports the check as
`SKIPPED` and points to the automatic GitHub Actions gate. When the Docker CLI
or daemon is unavailable, it also reports Docker/Compose checks as `SKIPPED`.
Any successful result with a skipped check is partial.

Before a deployment-related pull request, require full Docker/Compose local
validation:

```bash
scripts/ci-local --require-docker
```

The equivalent environment-variable interface is:

```bash
CI_LOCAL_REQUIRE_DOCKER=1 scripts/ci-local
```

Strict mode fails closed unless the Docker CLI is installed, the daemon is
reachable, the Docker Compose plugin is available, and both
`compose.prod.yml` and `compose.staging.yml` pass the repository Compose model
validator. It validates configuration only and does not start containers.

The final summary labels individual checks `PASS`, `FAIL`, or `SKIPPED` and
labels the overall result as full, partial, or failed. CI/CD remains the source
of truth for deployment validation; local strict mode is the closest
contributor-side parity check, not a replacement for protected CI.

Bandit is blocking in CI and local validation across `app`, `ops`, `config.py`,
`wsgi.py`, and `admin_wsgi.py`. Keep both customer and admin entrypoints in the
target list.

## Secret Scanning

Pull requests and pushes to `main` run the dedicated Gitleaks workflow in
addition to the custom repository secret scanner used by the main and local CI
paths. Never commit a real secret; make examples obviously fake. Gitleaks scans
full Git history with redacted output, uses no production secrets, and uploads
no SARIF or report artifact.

If Gitleaks fails, do not paste the matched value into a comment. Confirm false
positives privately and prefer rewriting the example; any remaining exception
must be a reviewed narrow allowlist for one fake/test value or public
non-secret metadata. Revoke and rotate a real credential immediately,
including a finding that exists only in Git history. See
`docs/security/assurance/secret-scanning.md` for the safe triage procedure.

## Static Analysis Gates

Three dedicated least-privilege workflows run automatically on pull requests
and pushes to `main`, with manual reruns:

- `.github/workflows/shellcheck.yml` uses checksum-verified ShellCheck 0.11.0
  against every tracked `.sh` file and supported shell shebang found by
  tracked-file discovery.
- `.github/workflows/hadolint.yml` uses checksum-verified Hadolint 2.14.0
  against every tracked `Dockerfile` and `Dockerfile.*`.
- `.github/workflows/semgrep.yml` uses the digest-pinned Semgrep 1.168.0
  container in local/OSS mode. It downloads registry rules but scans source
  locally with `--metrics=off`, needs no token, uploads no source or SARIF, and
  blocks ERROR severity.

Bash syntax checking catches parser errors; it is not a substitute for
ShellCheck. Keep scripts ShellCheck-clean, prefer fixes over suppressions, and
give every inline disable a narrow reason. Hadolint exceptions belong on the
affected instruction with a rationale. Semgrep suppressions must name the exact
rule and explain the reviewed safe boundary. These scanners complement tests,
container builds, and manual staging verification; they do not prove runtime
behavior.

Equivalent local commands are:

```bash
python ops/security/discover_lint_targets.py shell
python ops/security/discover_lint_targets.py dockerfile
shellcheck --severity=style <discovered shell paths>
hadolint --failure-threshold style <discovered Dockerfile paths>
semgrep scan --metrics=off --config p/python --config p/flask \
  --config p/security-audit --config p/owasp-top-ten \
  --config p/github-actions --severity ERROR --error .
```

After rollout is stable, branch protection should require all three workflow
checks. CI remains authoritative when a local tool is unavailable.

Dependabot PRs intentionally skip the human title/body prose validator. They
still require dependency review, dependency audit, lockfile validation, tests,
scanners, and manual review. Public PRs targeting `main` run dependency review
without `ENABLE_GITHUB_CODE_SECURITY`; private repositories require that
variable to be `true`.

Issue, PR, and manual-retag labels come from the shared bounded policy in
`ops/security/github_label_policy.py`. Automatic classification applies at
most six policy labels plus `needs-triage` for issues; broad guardrail and
validation boilerplate is ignored. See `docs/development/github-labeling.md`
before changing taxonomy or protected automation labels.

## SonarQube Cloud

Pull requests to `main` generate `coverage.xml` during the existing CI pytest
run and pass it to the downstream SonarQube job, so the full suite is not run
twice. The configured source/test scope is sent to SonarQube Cloud when the
trusted workflow can access `SONAR_TOKEN`. The initial quality gate is reporting-only,
so review the maintainability, duplication, reliability, security, and
coverage dashboard without treating its gate as a merge or deployment
approval. Fork pull requests run coverage but explicitly skip the secret-backed
upload. See `docs/security/assurance/sonarqube.md` for scope, exclusions, private-project
plan prerequisites, triage, and false-positive handling.
