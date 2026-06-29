# Test Automation And Dependencies

This document records the SITBank dependency inventory, security automation,
and test evidence found in the repository.

## Dependency Inventory

| Manifest or file | Purpose | Notes |
| --- | --- | --- |
| `requirements.in` | Top-level runtime Python dependencies | Flask, SQLAlchemy, Flask-WTF, Flask-Limiter, Flask-Talisman, PyOTP, Marshmallow, Cryptography, and related runtime packages |
| `requirements.lock` | Runtime Python lockfile | Generated with hashes and consumed by `pip-audit --require-hashes` |
| `requirements-dev.in` | Development/test dependencies | Includes `-r requirements.in`, `pytest`, `pytest-cov`, `pytest-xdist`, `pip-audit`, `bandit`, and `pip-tools` |
| `requirements-dev.lock` | Development/test lockfile | Generated with hashes and audited separately |
| `Dockerfile` | Runtime image | Uses a version tag plus immutable Python base-image digest for Dependabot tracking and reproducible builds, keeps application code root-owned and read-only, and runs as non-root UID/GID `10001:10001` |
| `compose.prod.yml` | Production deployment model | Uses Docker secrets, read-only app containers, loopback bindings, and separate customer/admin secret sets |
| `compose.staging.yml` | Staging deployment model | Uses separate staging secrets and database roles |
| `docker-compose.test.yml` | Test/CI compose model | Used by container smoke and validation flows |
| `ops/container/compose-validation.override.yml` | Compose validation override | Used by `ops/container/validate-compose.sh` |
| `.github/dependabot.yml` | Dependency update automation | Weekly Docker, GitHub Actions, and pip updates with limits and labels |
| `.github/workflows/ci-deploy.yml` | Main CI, image, smoke, scan, sign, and deploy workflow | Runs tests, audits, scans, DAST paths, Trivy, and cosign |
| `.github/workflows/codeql.yml` | CodeQL static analysis | Python `security-extended` queries on pull requests, main pushes, and schedule when repository is public |
| `.github/workflows/sonarqube.yml` | SonarQube Cloud code-quality analysis | Full pytest coverage plus reporting-only maintainability, duplication, reliability, and security dashboard analysis |
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
| GitHub dependency review | `.github/workflows/ci-deploy.yml` | Reviews dependency changes in pull requests |
| Trivy image scans | `.github/workflows/ci-deploy.yml` | Scans built images and repository filesystem paths; `.trivyignore` exceptions are tested |
| CodeQL | `.github/workflows/codeql.yml` | Runs Python security-extended static analysis when the repository is public |
| SonarQube Cloud | `.github/workflows/ci-deploy.yml`, `.github/workflows/sonarqube.yml`, `sonar-project.properties` | Reuses the CI test job's `coverage.xml` artifact to report private-repository code quality, duplication, maintainability, and security findings without rerunning pytest; initial quality gate is non-blocking |
| Bandit | `scripts/ci-local`, `.github/workflows/ci-deploy.yml` | Runs a high-confidence Python security scan |
| Secret scanner | `ops/security/scan_repository_secrets.py` | Scans tracked files and, in CI/local CI, git history for private keys and common token formats |
| Action hygiene | `.github/workflows/ci-deploy.yml` | Runs actionlint and zizmor; tests require actions to be SHA-pinned |
| Image and artifact signing | `.github/workflows/ci-deploy.yml`, `.github/workflows/bootstrap-ec2.yml`, `ops/deploy/sitbank-container-deploy` | Uses cosign to sign/verify images and deployment artifacts |

Tests for this automation include:

| Test | Coverage |
| --- | --- |
| `tests/test_pytest_optimization.py::test_ci_keeps_full_parallel_pytest_and_locked_dependency_checks` | CI keeps full unscoped pytest, pip check, Bandit, pip-audit, lock validation, and secret scan |
| `tests/test_pytest_optimization.py::test_local_ci_keeps_full_parallel_pytest_and_security_gates` | Local CI wrapper keeps the same security gates |
| `tests/test_deployment.py::test_dependency_manifests_have_one_hashed_lockfile_source_of_truth` | Dependency manifest policy |
| `tests/test_deployment.py::test_dependabot_tracks_docker_base_images_without_automerge` | Dependabot policy |
| `tests/test_deployment.py::test_every_github_action_is_pinned_to_a_full_commit_sha` | GitHub Actions pinning |
| `tests/test_deployment.py::test_trivy_exception_is_narrow_documented_and_temporary` | Trivy ignore policy |
| `tests/test_secret_scanner.py` | Secret scanner behavior |
| `tests/test_sonarqube_workflow.py` | SonarQube trigger, permission, pinning, coverage, scope, secret, label, and documentation policy |

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
| Password reset and manual recovery services | `tests/test_password_reset.py`, `tests/test_admin_manual_recovery.py` |
| Database session integrity | `tests/test_db_session_integrity.py` |
| Session management UI/API | `tests/test_session_management.py`, `tests/test_session_absolute_lifetime.py` |
| Auth bypass and pentest regressions | `tests/test_pentest_auth_bypass.py`, `tests/test_owasp_regressions.py` |
| Route inventory | `tests/test_route_inventory_security.py`, `tests/test_admin_route_inventory_security.py` |
| Admin isolation and staff invites | `tests/test_admin_isolation.py`, `tests/test_admin_staff_invites.py` |
| Banking payload and transaction guardrails | `tests/test_banking_transaction_security.py` |
| Audit, alerts, and redaction | `tests/test_audit_alerting.py`, `tests/test_audit_metadata_sanitization.py` |
| Deployment, Nginx, Docker, workflows, and runtime contracts | `tests/test_deployment.py` |
| UI security regressions | `tests/test_authenticated_portal_ui.py`, `tests/test_dashboard.py` |

Payee ownership, direct banking MFA gating, pre-TOTP lookup blocking,
duplicate/self-payee protections, expiry behavior, and removal IDOR are covered
by `tests/test_payee_management_security.py`.

Admin route authorization has a separate generated route-inventory matrix in
`tests/test_admin_route_inventory_security.py`, plus targeted admin service
tests for staff invites and manual recovery.

## Local Security Commands

The preferred local wrapper is:

```powershell
.\.venv\Scripts\python.exe scripts\ci-local
```

That wrapper runs the Python checks below, then Bash syntax checks, then
Compose validation if Docker is available.

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
| Python tests and checks | pytest, compileall, pip check, Bandit, pip-audit, lock validation, secret scan |
| Container smoke and DAST path | `ops/container/smoke-test.sh` |
| Trivy scans | Multiple Trivy action invocations for filesystem/image scan paths |
| Immutable image deployment | Image digest promotion and deployment tests |
| Cosign signing and verification | Image and deployment artifact signing/verification |
| Manual release DAST option | `workflow_dispatch` input `run_dast` controls authenticated DAST during release verification |

The separate `.github/workflows/codeql.yml` runs CodeQL Python
`security-extended` queries for public repository events. The separate
`.github/workflows/bootstrap-ec2.yml` signs bootstrap artifacts with cosign and
is covered by deployment tests.

The CI test job runs full-suite coverage once and uploads `coverage.xml`; its
downstream job calls reusable `.github/workflows/sonarqube.yml` to perform
reporting-only SonarQube Cloud analysis for the private repository. The
reusable job requires only `SONAR_TOKEN`, does not use deployment secrets or
rerun pytest, and does not change the existing CodeQL policy. Plan eligibility,
cloud source processing, scope,
exclusions, token rotation, triage, and limitations are documented in
`docs/security/sonarqube.md`.

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
| Synthetic account registration follows the real registration contract | `tests/test_deployment.py::test_dast_session_creator_matches_registration_contract` |
| Generated credentials are synthetic and random | `ops/container/create_dast_session.py` |
| The script emits an authenticated session cookie for ZAP rather than real user credentials | `ops/container/create_dast_session.py` |
| DAST cookie is not passed as a raw process argument | `tests/test_dast_helper_security.py::test_smoke_test_keeps_dast_cookie_out_of_host_command_arguments` |
| Temporary cookie and ZAP config files are created with restrictive permissions and cleanup | `tests/test_dast_helper_security.py::test_dast_secret_files_are_restricted_and_cleaned_up_by_contract` |

`ops/container/dast-smoke.sh` provides a local smoke-oriented DAST path using
synthetic secrets and a synthetic local test user. No real customer, admin, or
staff credentials are required by the DAST scripts in the repository.

The authenticated release/scheduled DAST path stores `auth-cookie` and
`zap-replacer.properties` only in the smoke-test temporary directory. The helper
sets `umask 077`, writes each secret file as `0600`, validates the cookie shape
inside the container, mounts the DAST directory read-only into ZAP, and passes
the non-secret scanner home option `-dir /zap/wrk/.ZAP` plus
`-configfile /run/dast/zap-replacer.properties` on the host-visible ZAP command
line. ZAP loads the authenticated-cookie replacer from a restricted file, so the
DAST cookie is not passed as a raw process argument. The temporary directory is
removed by the smoke-test cleanup trap on success and failure. ZAP's own cache,
browser profile, and report workspace run on container tmpfs so scanner-owned
files are discarded with the container instead of becoming host cleanup
artifacts.

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
tracked in `docs/security/security-gap-register.md`.

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
