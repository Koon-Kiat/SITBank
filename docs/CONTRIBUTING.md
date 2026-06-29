# Contributing

## Security Review

For security-sensitive changes, use
`docs/security/security-governance.md` to identify the owner role, review
trigger, accepted-risk handling, and documentation updates. Closing a security
gap should update the gap register, framework matrix, threat model, design risk
register, and runbooks when their claims changed.

## Local CI

Run the repository's normal local checks with:

```bash
scripts/ci-local
```

Normal mode runs the Python, package, security, Git Bash syntax, and whitespace
checks. When the Docker CLI or daemon is unavailable, it explicitly reports the
Docker/Compose checks as `SKIPPED`; that successful result is partial and does
not prove the deployment Compose models on the local machine.

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

## Secret Scanning

Pull requests and pushes to `main` run the dedicated Gitleaks workflow in
addition to the custom repository secret scanner used by the main and local CI
paths. Never commit a real secret; make examples obviously fake. Gitleaks scans
full Git history with redacted output, uses no production secrets, and uploads
no SARIF or report artifact.

If Gitleaks fails, do not paste the matched value into a comment. Confirm false
positives privately and prefer rewriting the example; any remaining exception
must be a reviewed narrow allowlist for one fake/test value. Revoke and rotate
a real credential immediately, including a finding that exists only in Git
history. See `docs/security/secret-scanning.md` for the safe triage procedure.

## SonarQube Cloud

Pull requests to `main` generate `coverage.xml` during the existing CI pytest
run and pass it to the downstream SonarQube job, so the full suite is not run
twice. The configured source/test scope is sent to SonarQube Cloud when the
trusted workflow can access `SONAR_TOKEN`. The initial quality gate is reporting-only,
so review the maintainability, duplication, reliability, security, and
coverage dashboard without treating its gate as a merge or deployment
approval. Fork pull requests run coverage but explicitly skip the secret-backed
upload. See `docs/security/sonarqube.md` for scope, exclusions, private-project
plan prerequisites, triage, and false-positive handling.
