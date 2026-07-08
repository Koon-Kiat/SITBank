# Test Automation And Dependencies

This document records the SITBank dependency inventory, security automation,
and test evidence found in the repository.

Category: [Security assurance](../README.md#assurance).

## Dependency Inventory

| Manifest or file | Purpose | Notes |
| --- | --- | --- |
| `requirements.in` | Top-level runtime Python dependencies | Flask, SQLAlchemy, Flask-WTF, Flask-Limiter, Flask-Talisman, PyOTP, Marshmallow, Cryptography, and related runtime packages |
| `requirements.lock` | Runtime Python lockfile | Generated with hashes and consumed by `pip-audit --require-hashes` |
| `requirements-dev.in` | Development/test dependencies | Includes `-r requirements.in`, `pytest`, `pytest-cov`, `pytest-xdist`, `pip-audit`, `bandit`, `pip-tools`, and Playwright for browser E2E tests |
| `requirements-dev.lock` | Development/test lockfile | Generated with hashes and audited separately |
| `Dockerfile` | Runtime image | Uses a version tag plus immutable Python base-image digest for Dependabot tracking and reproducible builds, keeps application code root-owned and read-only, and runs as non-root UID/GID `10001:10001` |
| `compose.prod.yml` | Production deployment model | Uses Docker secrets, read-only app containers, loopback bindings, and separate customer/admin secret sets |
| `compose.staging.yml` | Staging deployment model | Uses separate staging secrets and database roles |
| `docker-compose.test.yml` | Test/CI compose model | Used by container smoke and validation flows |
| `ops/container/compose-validation.override.yml` | Compose validation override | Used by `ops/container/validate-compose.sh` |
| `.github/dependabot.yml` | Dependency update automation | Weekly Docker, GitHub Actions, and pip updates with limits and labels |
| `.github/workflows/ci-deploy.yml` | Main CI, image, smoke, scan, sign, and deploy workflow | Runs tests, audits, scans, DAST paths, Trivy, and cosign |
| `.github/workflows/codeql.yml` | CodeQL static analysis | Python `security-extended` queries on pull requests, main pushes, and schedule when repository is public |
| `.github/workflows/gitleaks.yml` | Dedicated secret scanning | Gitleaks 8.30.1 scans full Git history on pull requests, `main` pushes, manual runs, and a weekly schedule with checksum-verified installation and redacted output |
| `.github/workflows/shellcheck.yml` | Repository shell static analysis | Checksum-verified ShellCheck 0.11.0 scans all tracked `.sh` files and supported shell shebangs discovered by the shared helper |
| `.github/workflows/hadolint.yml` | Dockerfile linting | Checksum-verified Hadolint 2.14.0 scans every tracked `Dockerfile` and `Dockerfile.*` discovered by the shared helper |
| `.github/workflows/semgrep.yml` | Automatic SAST | Digest-pinned Semgrep 1.168.0 runs local/OSS ERROR-severity scanning with metrics disabled on PRs, `main`, manual reruns, and a weekly schedule without a token, source upload, or SARIF |
| `.github/workflows/sonarqube.yml` | SonarQube Cloud code-quality analysis | Full pytest coverage plus a blocking trusted-run quality gate for maintainability, duplication, reliability, and security analysis |
| `.github/workflows/tailscale-private-admin-verify.yml` | Protected private-tailnet verification | A manual job joins with an ephemeral tagged identity; the direct environment-bound production gate performs the same reachability check after production deploy plus public TLS |
| `ops/tailscale/*` | Confirmation-gated Tailscale production-admin provisioning | Dry-run/confirm scripts install the authenticated package, support OAuth/auth-key/interactive enrollment, configure only private HTTPS to `127.0.0.1:5002`, delegate verification, and provide a non-secret ACL reference |
| `ops/deploy/verify-tailscale-admin-access` | EC2-local private-admin posture verification | A non-mutating production-host check validates Tailscale/Funnel state, loopback binding, readiness, Nginx absence, narrow Serve mapping, and private HTTPS without accepting credentials |
| `.github/workflows/bootstrap-ec2.yml` | Bootstrap artifact workflow | Uses pinned actions and cosign blob signing |

Not applicable to the current dependency inventory: no `package.json`,
`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `pyproject.toml`,
`poetry.lock`, or Pipenv files were found. JavaScript package auditing is not
applicable unless a frontend package manager is added.

## Dependency And Vulnerability Checks

| Check | Location | What it verifies |
| --- | --- | --- |
| Runtime `pip-audit` | `scripts/ci-local`, `.github/workflows/ci-deploy.yml` | Audits `requirements.lock` with `--disable-pip --require-hashes` |
| Dev `pip-audit` | `scripts/ci-local`, `.github/workflows/ci-deploy.yml` | Audits `requirements-dev.lock` separately |
| `pip check` | `scripts/ci-local`, `.github/workflows/ci-deploy.yml` | Verifies installed package metadata compatibility |
| Dependency lock validation | `ops/security/check_dependency_locks.py` | Enforces the hashed lockfile source of truth and rejects legacy dependency manifests |
| Dependabot | `.github/dependabot.yml` | Opens controlled weekly updates for Docker, GitHub Actions, and pip dependencies |
| GitHub dependency review | `.github/workflows/ci-deploy.yml` | Reviews dependency changes on public PRs targeting `main`; private repositories require `ENABLE_GITHUB_CODE_SECURITY=true`, while non-PR events intentionally skip it |
| Trivy image scans | `.github/workflows/ci-deploy.yml` | Uses pinned Trivy `v0.72.0` for built-image and repository filesystem scans; `.trivyignore` exceptions are tested |
| CodeQL | `.github/workflows/codeql.yml` | Runs Python security-extended static analysis when the repository is public |
| SonarQube Cloud | `.github/workflows/ci-deploy.yml`, `.github/workflows/sonarqube.yml`, `sonar-project.properties` | Reuses the CI test job's `coverage.xml` artifact without rerunning pytest; trusted PR and release-producing runs enforce the quality gate, and publication waits for SonarQube plus Playwright E2E |
| Playwright E2E | `.github/workflows/ci-deploy.yml`, `tests/e2e/` | Installs Chromium in a dedicated CI job and exercises browser-rendered authentication, MFA, session, banking, and boundary regressions against a loopback Flask server |
| Bandit | `scripts/ci-local`, `.github/workflows/ci-deploy.yml` | Runs a high-confidence Python security scan |
| Custom repository secret scanner | `ops/security/scan_repository_secrets.py` | Scans tracked files and, in CI/local CI, git history for private keys and common token formats |
| Gitleaks | `.github/workflows/gitleaks.yml`, `.gitleaks.toml` | Independently scans all refs with the built-in Gitleaks rules, redacted output, no production secrets, and no SARIF or raw report upload |
| ShellCheck | `.github/workflows/shellcheck.yml`, `ops/security/discover_lint_targets.py` | Fails on style-or-higher findings across repository-wide tracked-file discovery; Bash syntax remains a separate check |
| Hadolint | `.github/workflows/hadolint.yml`, `ops/security/discover_lint_targets.py` | Fails on style-or-higher findings for all discovered Dockerfiles |
| Semgrep | `.github/workflows/semgrep.yml` | Runs `p/python`, `p/flask`, `p/security-audit`, `p/owasp-top-ten`, and `p/github-actions` locally with `--metrics=off` and blocks ERROR severity |
| Action hygiene | `.github/workflows/ci-deploy.yml` | Runs actionlint and zizmor; tests require actions to be SHA-pinned |
| Image and artifact signing | `.github/workflows/ci-deploy.yml`, `.github/workflows/bootstrap-ec2.yml`, `ops/deploy/sitbank-container-deploy` | Uses cosign to sign/verify images and deployment artifacts |
| Release provenance | `.github/workflows/ci-deploy.yml` | Creates and verifies a GitHub artifact attestation for the exact release image digest, trusted repository, main ref, release commit, scheme-free `github.com/owner/repository/workflow` signer identity, GitHub OIDC issuer, and non-self-hosted runner before staging; public repositories allow Sigstore Public Good because GitHub artifact attestations use it, while the default GitHub API lookup avoids independent OCI BuildKit provenance; this is SLSA Build L1/L2-aligned evidence, not formal certification |

Tests for this automation include:

| Test | Coverage |
| --- | --- |
| `tests/test_pytest_optimization.py::test_ci_keeps_full_parallel_pytest_and_locked_dependency_checks` | CI keeps full unscoped pytest, pip check, Bandit, pip-audit, lock validation, and secret scan |
| `tests/test_playwright_e2e_config.py` | Playwright dependency lock, opt-in local browser execution, dedicated CI job, and documentation contract |
| `tests/test_pytest_optimization.py::test_local_ci_keeps_full_parallel_pytest_and_security_gates` | Local CI wrapper keeps the same security gates |
| `tests/test_deployment.py::test_dependency_manifests_have_one_hashed_lockfile_source_of_truth` | Dependency manifest policy |
| `tests/test_deployment.py::test_dependabot_tracks_docker_base_images_without_automerge` | Dependabot policy |
| `tests/test_deployment.py::test_every_github_action_is_pinned_to_a_full_commit_sha` | GitHub Actions pinning |
| `tests/test_deployment.py::test_trivy_exception_is_narrow_documented_and_temporary` | Trivy ignore policy |
| `tests/test_secret_scanner.py` | Secret scanner behavior |
| `tests/test_gitleaks_workflow.py` | Gitleaks triggers, permissions, checksum pinning, redaction, scope, config, custom-scanner preservation, and documentation consistency |
| `tests/test_lint_target_discovery.py` | Shell shebang, `.sh`, nested Dockerfile, deterministic output, and empty-discovery behavior |
| `tests/test_static_analysis_workflows.py` | ShellCheck, Hadolint, and Semgrep triggers, permissions, pinning, scope, blocking policy, secret boundaries, and documentation consistency |
| `tests/test_sonarqube_workflow.py` | SonarQube trigger, permission, pinning, coverage, scope, secret, label, and documentation policy |
| `tests/test_tailscale_ci_tailnet_workflow.py` | Private-tailnet trigger, environment, explicit OAuth/auth-key modes, action pinning, reachability, prohibited operation, and public TLS separation policy |
| `tests/test_tailscale_admin_access.py` | Host-preflight modes, bootstrap installation, safe command contract, Serve/Funnel parsing, listener failure cases, Nginx absence, and stubbed success/failure behavior |
| `tests/test_tailscale_admin_automation.py` | Provisioning files, dry-run/confirmation gates, secret handling, fixed Serve target, Funnel prohibition, bootstrap installation, ACL least privilege, and documentation contracts |

## Test Automation Coverage

The main Python test command is intentionally unscoped:

```powershell
.\.venv\Scripts\python.exe -m pytest -q -n auto --durations=30 --durations-min=0.5
```

This command is represented in `scripts/ci-local` and
`.github/workflows/ci-deploy.yml`. The tests cover security controls across
configuration, authentication, session integrity, access control, audit, and
deployment.

| Test area | Representative files |
| --- | --- |
| Configuration and secret validation | `tests/test_config.py`, `tests/test_deployment.py` |
| Registration, login, password policy, and rate limits | `tests/test_auth_registration_login.py`, `tests/test_passwords.py` |
| MFA lifecycle and envelope encryption | `tests/test_mfa_lifecycle.py`, `tests/test_mfa_envelope_crypto.py` |
| Password reset and manual recovery services | `tests/test_password_reset.py`, `tests/test_admin_manual_recovery.py`, `tests/test_admin_maker_checker.py` |
| Database session integrity | `tests/test_db_session_integrity.py` |
| Session management UI/API | `tests/test_session_management.py`, `tests/test_session_absolute_lifetime.py` |
| Auth bypass and pentest regressions | `tests/test_pentest_auth_bypass.py`, `tests/test_owasp_regressions.py` |
| Route inventory and admin role permissions | `tests/test_route_inventory_security.py`, `tests/test_admin_route_inventory_security.py`, `tests/test_admin_rbac_matrix.py` |
| Admin isolation and staff invites | `tests/test_admin_isolation.py`, `tests/test_admin_staff_invites.py` |
| Banking payload and transaction guardrails | `tests/test_banking_transaction_security.py` |
| Audit, alerts, and redaction | `tests/test_audit_alerting.py`, `tests/test_audit_metadata_sanitization.py` |
| Deployment, Nginx, Docker, workflows, and runtime contracts | `tests/test_deployment.py` |
| UI security regressions | `tests/test_authenticated_portal_ui.py`, `tests/test_dashboard.py` |
| Browser E2E regressions | `tests/e2e/test_customer_auth_browser.py`, `tests/e2e/test_customer_mfa_browser.py`, `tests/e2e/test_customer_registration_recovery_browser.py`, `tests/e2e/test_customer_banking_browser.py`, `tests/e2e/test_session_security_browser.py`, `tests/e2e/test_customer_admin_boundary_browser.py`, `tests/e2e/test_sensitive_browser_artifacts.py` |

Payee ownership, direct banking MFA gating, pre-TOTP lookup blocking,
duplicate/self-payee protections, expiry behavior, and removal IDOR are covered
by `tests/test_payee_management_security.py`.

Admin route authorization has a separate generated route inventory in
`tests/test_admin_route_inventory_security.py`. A centralized role-permission
matrix in `tests/test_admin_rbac_matrix.py` exercises unauthenticated,
customer-isolated, staff, admin, and root-admin access to representative read
and mutation routes and verifies denied mutations have no privileged side
effects. Targeted service tests retain deeper coverage for staff invites,
manual recovery, direct root-admin actions, legacy approval-record handling,
and the manual-only root-admin bootstrap boundary.

Playwright E2E browser tests cover authentication, MFA, session, banking, and
boundary regressions, including registration, password reset, manual recovery,
payee, transfer, session management, password change, account freeze, and
customer/admin isolation, against a loopback Flask server. They are opt-in for local
unscoped pytest because they require browser binaries, and they do not prove
live staging or production provider state. To run them locally:

```powershell
$env:PLAYWRIGHT_BROWSERS_PATH = ".playwright-browsers"
.\.venv\Scripts\python.exe -m playwright install chromium
$env:SITBANK_RUN_E2E = "1"
.\.venv\Scripts\python.exe -m pytest -q tests/e2e
```

The CI `Playwright E2E browser tests` job installs Chromium with `python -m
playwright install --with-deps chromium`, sets `SITBANK_RUN_E2E=1`, and runs
`python -m pytest -q tests/e2e`. Browser cache and report paths stay under
ignored local paths such as `.playwright-browsers`, `playwright-report`, and
`test-results`; the workflow does not upload traces, videos, cookies, or
browser profiles.

The normal suite reuses one customer app and one admin app with their database
schemas per xdist worker.
Every test still receives isolated database rows, server-side sessions,
rate-limit state, fake delivery state, and app configuration. Tests that
specifically prove factory, admin/customer database, migration, hashing,
authentication, MFA, or session-creation behavior continue to use their real
paths. Xdist `auto` is capped at four workers so high-core hosts do not
overcommit the in-memory SQLite test workload. The history secret scanner
preserves full reachable-history coverage while reading metadata and content
through streaming Git object batches.
There are no marker exclusions or scoped test paths in the required full-suite
command.

Deterministic TOTP timestamps are test-only helpers: they remove wall-clock
sleep while still exercising valid, invalid, replay, and expiry boundaries.
Production verification remains time-window based. Helper-created
authenticated state is appropriate only when login, password hashing, MFA,
session creation, and password history are not the behavior under test; those
security flows retain dedicated real-path coverage.

## Local Security Commands

The preferred local wrapper is:

```powershell
.\.venv\Scripts\python.exe scripts\ci-local
```

That wrapper runs the Python checks below, discovered Bash syntax checks,
ShellCheck/Hadolint/Semgrep when installed, then Compose validation if Docker
is available. Missing optional local scanners are explicit `SKIPPED` results;
their automatic GitHub Actions workflows remain authoritative.

```powershell
.\.venv\Scripts\python.exe -m pytest -q -n auto --durations=30 --durations-min=0.5
.\.venv\Scripts\python.exe -m compileall app config.py wsgi.py admin_wsgi.py
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m bandit -q -ll -r app ops config.py wsgi.py admin_wsgi.py
.\.venv\Scripts\python.exe -m pip_audit --disable-pip --require-hashes -r requirements.lock
.\.venv\Scripts\python.exe -m pip_audit --disable-pip --require-hashes -r requirements-dev.lock
.\.venv\Scripts\python.exe ops\security\check_dependency_locks.py
.\.venv\Scripts\python.exe ops\security\scan_repository_secrets.py --history
git diff --check
```

Shared target discovery and equivalent scanner commands are:

```powershell
.\.venv\Scripts\python.exe ops\security\discover_lint_targets.py shell
.\.venv\Scripts\python.exe ops\security\discover_lint_targets.py dockerfile
shellcheck --severity=style <discovered shell paths>
hadolint --failure-threshold style <discovered Dockerfile paths>
semgrep scan --metrics=off --config p/python --config p/flask --config p/security-audit --config p/owasp-top-ten --config p/github-actions --severity ERROR --error .
```

The Semgrep command is local/OSS mode. Registry rules are downloaded, but
source is scanned locally and is not uploaded; no token is required.

The GitHub workflow command block in `.github/workflows/ci-deploy.yml` runs the
same core checks. Its Bandit command currently scans `app`, `ops`, `config.py`,
and `wsgi.py`; the local wrapper additionally includes `admin_wsgi.py`.

Local Docker note: `scripts/ci-local` skips Docker/Compose-only checks in normal
mode when Docker is unavailable. The skipped result is explicit and partial;
Compose validation still runs in CI and on local machines with Docker available.
For deployment-impacting local validation, use
`scripts/ci-local --require-docker` or
`CI_LOCAL_REQUIRE_DOCKER=1 scripts/ci-local`; strict mode fails closed unless
Docker, Docker Compose, and the production/staging Compose model validation all
run successfully.

## CI/CD Security Automation

The main workflow in `.github/workflows/ci-deploy.yml` includes these security
stages:

| Stage | Evidence |
| --- | --- |
| Workflow hygiene | actionlint installation plus zizmor action |
| Dependency review | `actions/dependency-review-action` |
| Python tests and checks | pytest, compileall, pip check, Bandit, pip-audit, lock validation, custom repository secret scan |
| Dedicated secret scan | Gitleaks 8.30.1 full Git history workflow with checksum-verified CLI and redacted output |
| Shell static analysis | ShellCheck 0.11.0 scans tracked-file discovery output; `bash -n` remains a distinct syntax check |
| Dockerfile linting | Hadolint 2.14.0 scans all discovered Dockerfiles with an instruction-scoped documented exception only |
| SAST | Semgrep 1.168.0 local/OSS registry rules block ERROR severity with no token, source upload, SARIF, or production secrets |
| Container smoke and DAST path | `ops/container/smoke-test.sh` |
| Trivy scans | Multiple Trivy action invocations for filesystem/image scan paths |
| Immutable image deployment | Image digest promotion and deployment tests |
| Cosign signing and verification | Image and deployment artifact signing/verification |
| Manual release DAST option | `workflow_dispatch` input `run_dast` controls authenticated DAST during release verification |

Private admin reachability is isolated in protected environment-bound jobs.
`.github/workflows/tailscale-private-admin-verify.yml` runs manually, and the
main production workflow implements its required direct gate after production
deploy and public production TLS succeed. The direct production job avoids the
reusable-call secret-scope failure and enters the protected `admin-tailscale`
environment after manual approval. Production uses OAuth with
`TS_OAUTH_CLIENT_ID`/`TS_OAUTH_SECRET`; manual runs may select the optional
`TAILSCALE_AUTH_KEY`. Both identities are limited to
`tag:github-ci-admin-verify -> tag:admin-sitbank:443`. The job runs no pull-request code,
checks the private URL is unreachable before joining, validates the private
login entrypoint, and logs out without artifacts. Normal public TLS scans never include
`admin-sitbank.tailca101b.ts.net`.

Credential rotation and offboarding require replacing and testing the selected
OAuth client or auth key before revocation, removing stale CI nodes, reviewing
environment approvers/branch rules, and removing the dedicated CI
grants/environment when access is no longer required. This workflow does not enable Tailscale
Funnel or Serve and does not replace Flask admin login, TOTP, CSRF,
authorization, audit logging, or host-side Tailscale verification.

Repository-managed provisioning lives in `ops/tailscale/`. Its Bash scripts
are covered by static and dry-run contract tests; normal CI never runs
installation, `tailscale up`, or Serve configuration. Mutating host execution
requires `--confirm`, an explicit auth mode, approved operator access, and
post-change verification. The complementary EC2 host control is
`/usr/local/sbin/verify-tailscale-admin-access --mode serve`, installed by the
production bootstrap. Normal CI does not contact a live daemon: it uses
stubbed command results to cover Running-state parsing, Funnel rejection,
loopback-only listeners, local readiness, Nginx absence, narrow Serve mapping,
private HTTPS, and fail-closed behavior. The canonical verifier has no provisioning path
and accepts no Tailscale credential. A successful live run is operator-owned
deployment evidence; ACL, device approval, and membership remain separate
manual evidence.

The separate `.github/workflows/codeql.yml` runs CodeQL Python
`security-extended` queries for public repository events. The separate
`.github/workflows/bootstrap-ec2.yml` signs bootstrap artifacts with cosign and
is covered by deployment tests.

The CI test job runs full-suite coverage once and uploads `coverage.xml`; its
downstream job calls reusable `.github/workflows/sonarqube.yml` to perform
blocking SonarQube Cloud quality-gate analysis for trusted events. The reusable
job requires only `SONAR_TOKEN`, does not use deployment secrets or rerun
pytest, and does not change the existing CodeQL policy. Fork and Dependabot PRs
skip the secret-backed scan explicitly. Plan eligibility, cloud source processing, scope,
exclusions, token rotation, triage, and limitations are documented in
`docs/security/assurance/sonarqube.md`.

Tests in `tests/test_deployment.py` assert that these workflow controls remain
present, including dependency review, action pinning, Trivy policy, cosign, and
DAST policy.

## Authenticated DAST And Smoke Tests

Container smoke tests live in `ops/container/smoke-test.sh`. The script pins the
ZAP image as `zaproxy/zap-stable:2.17.0@sha256:...` and runs authenticated DAST
only when `RUN_ZAP_DAST=true`.

Authenticated DAST session creation is handled by
`ops/container/create_dast_session.py`:

| Control | Evidence |
| --- | --- |
| Target host restricted to loopback or explicit smoke host | `tests/test_deployment.py::test_dast_session_creator_requires_loopback_or_explicit_smoke_host` |
| Session bootstrap restricted to `DEPLOYMENT_TARGET=smoke` | `tests/test_dast_helper_security.py::test_issue_dast_session_cookie_rejects_non_smoke_runtime` |
| Session bootstrap rejects non-synthetic and privileged users | `tests/test_dast_helper_security.py::test_issue_dast_session_cookie_rejects_non_synthetic_or_privileged_users` |
| Synthetic account registration follows the real registration contract | `tests/test_deployment.py::test_dast_session_creator_matches_registration_contract` |
| Generated credentials are synthetic and random | `ops/container/create_dast_session.py` |
| The script emits an authenticated session cookie for ZAP rather than real user credentials | `ops/container/create_dast_session.py` |
| DAST cookie is not passed as a raw process argument | `tests/test_dast_helper_security.py::test_smoke_test_keeps_dast_cookie_out_of_host_command_arguments` |
| Temporary cookie and ZAP config files are created with restrictive permissions and cleanup | `tests/test_dast_helper_security.py::test_dast_secret_files_are_restricted_and_cleaned_up_by_contract` |
| Turnstile dummy-token action is accepted only in release smoke | `tests/test_turnstile_public_auth.py::test_turnstile_verifier_accepts_test_action_only_for_explicit_test_keys` |

`ops/container/dast-smoke.sh` provides a local smoke-oriented DAST path using
synthetic secrets and a synthetic local test user. No real customer, admin, or
staff credentials are required by the DAST scripts in the repository.
The server-side session primitive fails before issuance unless the runtime
target is exactly `smoke`, the customer matches the helper's complete
`zap<12-lowercase-hex>` identity contract, MFA is already enabled, and the
session host is loopback or `sitbank-smoke`. Existing-username collisions,
stale or malformed synthetic records, real customers, and staff, admin, and
root-admin identities fail closed.

The authenticated release/scheduled DAST path stores `auth-cookie` and
`zap-replacer.properties` only in the smoke-test temporary directory. The helper
sets `umask 077`, writes each secret file as `0600`, validates the cookie shape
inside the container, mounts the DAST directory read-only into ZAP, and submits
Cloudflare's official dummy token only to the isolated smoke app with official
test keys, `DEPLOYMENT_TARGET=smoke`, and `TURNSTILE_ALLOW_TEST_ACTION=true`.
Production readiness rejects that flag outside the smoke target. The ZAP
command passes the non-secret scanner
home option `-dir /zap/wrk/.ZAP` plus
`-configfile /run/dast/zap-replacer.properties` on the host-visible ZAP command
line. ZAP loads the authenticated-cookie replacer plus the non-secret
`User-Agent`, `X-Forwarded-For`, and `X-Forwarded-Proto` smoke identity headers
from a restricted file, so the DAST cookie is not passed as a raw process
argument and the crawl matches the server-side session risk context. The
temporary directory is removed by the smoke-test cleanup trap on success and
failure. ZAP's own cache, browser profile, and report workspace run on container
tmpfs so scanner-owned files are discarded with the container instead of
becoming host cleanup artifacts.

The DAST bind-mount directory is relaxed for container UID compatibility, but
the secret files inside remain owner-only and are not uploaded as GitHub
artifacts. GitHub Actions must not print environment dumps, cookie values, CSRF
tokens, synthetic passwords, or full ZAP replacer contents. If `auth-cookie` or
`zap-replacer.properties` appears in a log or artifact, cancel the run, delete
the artifact, revoke the synthetic session by ending the run, and review the
workflow/script diff before rerunning.

Authenticated DAST is release-oriented. Ordinary pull requests skip the full
authenticated crawl for runtime cost, while scheduled runs and release
verification paths enable it according to workflow policy. The tradeoff is
tracked in `docs/security/governance/security-gap-register.md`.

## Dependency Update Workflow

Dependabot is configured in `.github/dependabot.yml`:

| Ecosystem | Schedule | Limits |
| --- | --- | --- |
| Docker | Weekly Monday, Asia/Singapore timezone | Pull request limit 3; Python 3.13+ base images ignored |
| GitHub Actions | Weekly Monday | Pull request limit 5 |
| pip | Weekly Monday | Pull request limit 8; patch/minor grouping; cooldowns for major/minor/patch changes |

Dependabot does not auto-merge updates in the repository configuration
inspected. Updates must still pass the lockfile policy, tests, audits, scans,
and review workflow.

## Supply-Chain Evidence

The source SBOM workflow at `.github/workflows/sbom.yml` uses pinned Syft
1.46.0 to create `sitbank-source-sbom-cyclonedx.json`, validates it as JSON,
and retains the `sitbank-source-sbom` CycloneDX JSON artifact for 30 days. It
runs without secrets on pull requests, pushes to `main`, and manual dispatch.
Before scanning, the workflow copies the source-controlled
`requirements.lock` and `requirements-dev.lock` to temporary
`*requirements*.txt` names recognized by Syft and disables the installed
Python package cataloger. This keeps runner-global packages, runner
`site-packages`, and local `.venv` contents out of the source dependency
count. Its bounded summary puts the Python section first, matches emitted
`pkg:pypi/` PURLs to pinned packages in those reviewed source-controlled
manifests, limits the preview to 10 rows, and places the all-component
ecosystem table last. If manifests exist but no matching PyPI PURLs are
emitted, zero is described as a generator/PURL detection limitation rather
than proof of no Python dependencies. The renderer reads only relative
regular-file paths contained by the current workspace and rejects traversal
and symlink escapes. The full `sitbank-source-sbom` artifact remains the source
of truth. Inspect its Python inventory with
`jq -r '(.components // [])[] | select((.purl // "") | startswith("pkg:pypi/")) | [.name, .version, .purl] | @tsv' sitbank-source-sbom-cyclonedx.json`.
Installed runtime packages belong to image/container SBOM scope. The source
artifact is separate from Buildx image attestation and is not vulnerability scanning.
The existing Buildx `sbom: true` attestation remains required; an explicit
image SBOM artifact remains deferred until the exact digest-verified release
image is safely available to the evidence job.

The informational `.github/workflows/scorecard.yml` runs on `main`, weekly, and
manually. It uploads `openssf-scorecard-results` for 30 days, does not publish
results, and is not a required pull-request check. Record the numeric baseline
and key findings after the first merged run rather than inventing provider
evidence in repository documentation.

The latest reviewed Dependency Review run on 2026-07-02 reported no high-or-
higher vulnerabilities or denied packages and showed an upstream OpenSSF
Scorecard score of `6.9` for the newly pinned
`tailscale/github-action`. That `6.9` is the dependency repository's score, not
SITBank's repository baseline. The public Scorecard API had no SITBank result
before rollout; the first successful merged `scorecard.yml` run remains the
authoritative SITBank baseline.

| Scorecard check | Classification | Repository evidence or follow-up |
| --- | --- | --- |
| `Token-Permissions` | Fixed and test-covered | Every workflow defaults to no permissions or read-only access; the narrow job-level write allowlist is asserted by `tests/test_scorecard_workflow.py` |
| `Branch-Protection` | `provider-state-only` | Expected `main` rules are documented; retain sanitized ruleset evidence because repository files cannot prove live enforcement |
| `SAST` | Implemented; a missing result is a false positive | CodeQL, Semgrep, and SonarQube Cloud remain enabled and test-covered |
| `Packaging` | Implemented with a project-specific release model | The release unit is a digest-pinned GHCR image, not a traditional GitHub release asset |
| `Signed-Releases` | Implemented; a release-asset-only warning is a false positive | Cosign/OIDC signs the GHCR digest and deployment verifies certificate identity |
| `CII-Best-Practices` | Accepted backlog | A badge or registration alone would not strengthen a runtime control; track only if maintainers adopt the program |
| `Fuzzing` | Accepted backlog | Existing property/negative tests remain; add a reviewed fuzzing issue when stable targets and triage ownership exist |

Warnings about the pinned `tailscale/github-action` dependency can describe
that upstream repository rather than SITBank. Classify them as upstream
evidence, not proof that SITBank lacks its own token, SAST, packaging, or
signing controls. `CII-Best-Practices` and `Fuzzing` remain accepted backlog
items. Do not chase a perfect score by broadening tokens, mutating
provider state, weakening deployment gates, or duplicating scanners.
