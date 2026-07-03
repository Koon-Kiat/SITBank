# GitHub Actions

## Release Flow

The normal release path is:

```text
main push -> Publish container image -> Release verification -> Deploy staging
  -> Verify staging TLS -> Deploy production -> Verify production TLS
  -> Verify private admin tailnet
```

The tested, scanned, signed, and deployed digest must be identical. Deployments never use `latest`.

## Workflow And Check Display Names

Every workflow job and visible step has an explicit human-readable display
name. Internal job IDs remain stable kebab-case keys because `needs:`
dependencies, expressions, and repository tests refer to them. The Actions UI
and status checks use the display names:

| Internal job ID | Visible job/check name |
| --- | --- |
| `resolve-source` | `Resolve source` |
| `workflow-security` | `Workflow security` |
| `dependency-review` | `Dependency review` |
| `test` | `Test and security checks` |
| `playwright-e2e` | `Playwright E2E browser tests` |
| `sonarqube` | `SonarQube analysis` |
| `sonarqube-comment` | `SonarQube PR comment` |
| `image-test` | `Container image test` |
| `deployment-preflight` | `Deployment preflight` |
| `publish` | `Publish container image` |
| `release-verify` | `Release verification` |
| `deploy-staging` | `Deploy staging` |
| `verify-staging-tls` | `Verify staging TLS` |
| `deploy-production` | `Deploy production` |
| `verify-production-tls` | `Verify production TLS` |
| `verify-private-admin-tailnet` | `Verify private admin tailnet` |

Bootstrap, Cloudflare verification, label automation, reusable SonarQube, and
manual private-tailnet jobs follow the same explicit naming policy. The
manual **Verify private Grafana Loki observability** workflow is a protected
post-deployment evidence workflow for the private observability stack, not a
pull-request or public TLS check.
`tests/test_workflow_display_names.py` enforces the policy across every
`.github/workflows/*.yml` file while allowing the intentional TLS matrix name
`Scan ${{ matrix.target.label }}`.

## Non-Deploy Security Summaries

Each independent security job outside `.github/workflows/ci-deploy.yml` writes
a bounded, human-readable `GITHUB_STEP_SUMMARY`. Scanner summaries identify
the checked scope, decision, safe finding counts, and artifact or code-scanning
location where applicable. Detailed logs, individual job summaries, SARIF
views, and retained artifacts remain the source of truth; summaries never copy
secret matches or full raw scanner payloads.

`.github/workflows/security-summary.yml` adds a shorter read-only rollup for
pull requests and for merged commits pushed to `main`. It waits for the
event-appropriate independent jobs, distinguishes passed, failed, skipped,
expected-skipped, pending, and unknown states, and fails closed for any
unresolved or unexpected state. Its one `CI, publish, and deploy` row is only a
scope pointer and does not duplicate findings from `ci-deploy.yml`. The rollup
does not replace individual checks, change branch-protection contexts, post a
PR comment, publish, or deploy.

The `Playwright E2E browser tests` job (internal ID `playwright-e2e`) installs
the hashed development dependencies, installs Chromium with `python -m
playwright install --with-deps chromium`, and runs `python -m pytest -q
tests/e2e` with `SITBANK_RUN_E2E=1` and `PLAYWRIGHT_BROWSERS_PATH` set to
`.playwright-browsers`. The tests use a loopback Flask server from the pytest
app fixture for authentication, MFA, session, banking, and boundary
regressions. Coverage includes registration, password reset, manual recovery, payee, transfer, session management, password change, account freeze, and customer/admin isolation.
They do not prove live staging or production provider state and do
not target staging, production, or private-admin hosts. Browser cache, reports,
traces, screenshots, and videos are ignored and are not uploaded by the job.

The Python suite uses a per-worker app and database schema with per-test state
cleanup, and the custom full-history secret scan reads streaming Git object
batches. These runtime optimizations do not add marker exclusions, scoped test
paths, or weaker security checks.

Changing a job display name can change its required status-check context even
when the internal ID is unchanged. Repository files do not update GitHub
rulesets. After merging a display-name change, let the new check complete,
update any affected required context in GitHub settings, and only then remove
the old context, following
`docs/security/governance/github-branch-protection-evidence.md`.

Production never skips disabled, skipped, or failed staging. It runs only after
release verification and staging deployment both succeed on `main`, with
`PROD_DEPLOY_ENABLED = true` and GitHub production environment approval.
Production deployment is environment-approved automatic after successful
staging gates. The environment approval is a manual gate, not a manual-only
production dispatch path.

Configure the GitHub `production` Environment with required trusted reviewers,
deployment branches limited to `main`, and production-only variables and
secrets. Repository files describe that contract but do not prove the live
provider-side reviewers or branch rules; retain a sanitized settings review as
release evidence.

## Pull Request Policy and Dependency Review

The human PR title and description workflow applies to contributor PRs.
Dependabot PRs skip that prose-only policy because their generated title and
body follow GitHub's dependency-update format. They remain subject to
dependency review, dependency audit, lockfile checks, tests, scanners, and
manual maintainer review; no `pull_request_target`, write token, or secret is
introduced for that exception.

The `Dependency review` check (internal job ID `dependency-review`) is PR-only.
Public PRs targeting `main` are
eligible without `ENABLE_GITHUB_CODE_SECURITY`. A private repository must set
that variable to `true`; pushes, schedules, and manual deployment runs
intentionally skip the comparison-only job. If it is unexpectedly skipped,
confirm the event is a PR targeting `main`, repository visibility, feature
availability, and required-check configuration before changing permissions.

## Manual Pre-Merge Staging

Manual pre-merge staging:

1. run trusted workflow from main;
2. set `source_ref = candidate branch, tag, or SHA`;
3. resolve immutable source_sha;
4. build, test, scan, sign, and verify the candidate image;
5. deploy staging using trusted main scripts.

Feature-branch workflow and deployment scripts are never executed with environment secrets. The only accepted migration mode for existing EC2 deployment files is `adopt-existing`, and it must still pass wrapper hash validation before app deployment.

The SSH deployment jobs and trusted-main EC2 bootstrap jobs join Tailscale
before any `ssh` or `scp` command and always log out afterward. Staging uses
`tag:github-ci-staging-deploy` and production uses
`tag:github-ci-prod-deploy`; each protected environment stores its own
`TS_OAUTH_CLIENT_ID` and `TS_OAUTH_SECRET`. OpenSSH still requires the
environment-specific deploy key, pinned known-hosts entry, and
`StrictHostKeyChecking=yes`. Tailscale SSH remains disabled.

## Environment Variables

GitHub environment variables provide only non-secret deployment settings. Keep
`STAGING_DEPLOY_ENABLED` and `PROD_DEPLOY_ENABLED` as repository variables. Put
environment-specific non-secret settings, including SMTP sender/host values,
under their matching GitHub environment. For both `staging` and `production`,
set these environment variables:

- `<PREFIX>_EC2_HOST`
- `<PREFIX>_EC2_PORT`
- `<PREFIX>_EC2_DEPLOY_USER`
- `<PREFIX>_PUBLIC_HOST`
- `<PREFIX>_MFA_KEK_ACTIVE_ID`
- `<PREFIX>_SESSION_HMAC_ACTIVE_KEY_ID`
- `<PREFIX>_PASSWORD_PBKDF2_ITERATIONS`
- `<PREFIX>_MFA_ISSUER_NAME`
- `<PREFIX>_PASSWORD_RESET_EMAIL_FROM`
- `<PREFIX>_SMTP_HOST`

Root-admin allowlists are sensitive privileged-identity configuration, not
repository variables. Store `STAGING_ROOT_ADMIN_EMAILS` in the protected
`staging` environment with exactly 2 workplace addresses and
`PROD_ROOT_ADMIN_EMAILS` in `production` with exactly 5 workplace addresses.
Every address must belong to `ADMIN_ALLOWED_EMAIL_DOMAINS`. The deployment
workflow maps only the target's secret into the renderer input and validates
only its shape, and installs it as the root-managed secret file
`/etc/sitbank*/secrets/root_admin_emails`. Do not copy the real allowlist into
issues, pull requests, screenshots, logs, or job summaries.

`STAGING_PUBLIC_HOST` and `PROD_PUBLIC_HOST` are public HTTPS verification
names. `STAGING_EC2_HOST` and `PROD_EC2_HOST` are private Tailscale MagicDNS
names or `100.x.y.z` addresses used only for deployment and bootstrap OpenSSH.
Regenerate the matching `*_EC2_KNOWN_HOSTS` value for that private target and
verify its fingerprint out of band before saving it. After both private paths
succeed, remove public port `22` exposure from the EC2 security group and host
firewall. Public SSH is not a workflow fallback; retain approved AWS
console/SSM access or a tightly scoped, time-limited security-group break-glass
procedure for host recovery.

For production only, also set:

- `PROD_ADMIN_SESSION_HMAC_ACTIVE_KEY_ID`
- `PROD_ADMIN_SESSION_KEY_PREFIX` if overriding the default `admin-session:`
- `PROD_ADMIN_RATELIMIT_KEY_PREFIX` if overriding the default `ospbank:admin:ratelimit:`

For staging admin, also set:

- `STAGING_ADMIN_SESSION_HMAC_ACTIVE_KEY_ID`

For the staging customer Access assertion gate, also set:

- `STAGING_CLOUDFLARE_ACCESS_AUD`
- `STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN`

`ops/cloudflare/provision-staging-access --apply` prints both values after it
creates or reconciles the Access application. They are identifiers rather than
secrets, but keep them in the protected `staging` environment so deployment
and provider configuration change together.

The manual **Verify staging Cloudflare Access** workflow runs only from `main`
in the protected `staging` environment. That shared environment requires:

- `CLOUDFLARE_API_TOKEN`
- `STAGING_ACCESS_ALLOWED_EMAILS`
- `STAGING_DNS_ORIGIN`
- `STAGING_ORIGIN_IP`
- `STAGING_EC2_KNOWN_HOSTS`
- `STAGING_EC2_SSH_PRIVATE_KEY_B64`

The provider workflow consumes the first four values; the two EC2 credentials
remain deployment-only. `STAGING_ACCESS_ALLOWED_GROUP_IDS` is optional when the policy uses only the
exact explicit emails in `STAGING_ACCESS_ALLOWED_EMAILS`. Required environment
variables are `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_ZONE_ID`,
`STAGING_ACCESS_SESSION_DURATION`, `STAGING_CLOUDFLARE_ACCESS_AUD`,
`STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN`, `STAGING_PUBLIC_HOST`,
`STAGING_EC2_HOST`, `STAGING_EC2_DEPLOY_USER`, and `STAGING_EC2_PORT`.
`STAGING_ACCESS_ALLOWED_IDP_IDS` is optional unless a reviewed IdP restriction
is active. The provider workflow maps every supported Cloudflare value; the
EC2 host, user, and port remain deployment-only.
`STAGING_ACCESS_APP_NAME` and `STAGING_ACCESS_POLICY_NAME` are optional;
leaving them empty uses the reviewed defaults.

The reviewed provider values are `STAGING_ACCESS_SESSION_DURATION=6h`,
`STAGING_PUBLIC_HOST=staging-sitbank.pp.ua`, application name `SITBank
staging`, and policy name `SITBank staging app - approved operators only`.
`Everyone`, wildcard domains, and broad allow-all rules are forbidden. The
separate App Launcher policy is `SITBank Access launcher - approved operators
only`; it remains manual Cloudflare-side configuration unless repository
automation is explicitly expanded to manage it later. Run the workflow
manually after any provider or environment change; safe drift output names
non-secret fields and reports allowlist mismatches by count without printing
emails, tokens, headers, cookies, JWTs, or Access assertions.
The staging bootstrap job also runs this read-only verification before any EC2
mutation. The root deployment wrapper independently checks the live edge
challenge and loopback direct-origin denial before switching the staging
runtime. This ordering makes Cloudflare Access and direct-origin denial
prerequisites for installing the Basic-Auth-free Nginx edge or changing the
application behind it.
The uploaded JSON is intentionally sanitized and retained for 30 days. It
contains no provider export or raw HTTP response. GitHub secret masking is
defense in depth; the automation also redacts authentication headers, bearer
tokens, JWTs, service tokens, cookies, session identifiers, CSRF values, and
private-key blocks before printing handled errors.

`<PREFIX>_MFA_KEK_ACTIVE_ID` must match a key identifier in the root-managed `/etc/sitbank*/secrets/mfa_kek_keys_json` file on EC2. Do not put `MFA_KEK_KEYS_JSON` in GitHub Actions; the KEK keyring is a long-lived secret and remains host-managed.
`<PREFIX>_ADMIN_SESSION_HMAC_ACTIVE_KEY_ID` must match a key identifier in
`/etc/sitbank*/secrets/admin_session_hmac_keys_json`. Do not put admin Flask,
CSRF, session-HMAC, session-lookup HMAC, password-pepper, or database secret values in GitHub
Actions; those remain root-managed EC2 secret files.
`SECURITY_AUDIT_HMAC_KEY` is also a root-managed EC2 secret file and is not
exported through GitHub Actions environment variables.
Do not pass root-admin passwords, TOTP secrets, QR codes, provisioning URIs, or
TOTP setup values through GitHub Actions. Root-admin bootstrap remains a
manual-only operator command run over SSH inside the private admin container
after deployment. It must not run from GitHub Actions, deployment automation,
non-interactive bootstrap wrappers, workflow inputs, job summaries, artifacts,
or repository/environment secrets. Any future automation must be a separate
reviewed design with protected environment approval and explicit tests proving
that bootstrap passwords, TOTP secrets, QR codes, provisioning URIs, and setup
values never enter logs or artifacts.

## Private Tailnet Verification

`.github/workflows/tailscale-private-admin-verify.yml` is manual-runnable.
The trusted production workflow implements the same protected check directly
as its required `Verify private admin tailnet` gate after the internal
`deploy-production` and `verify-production-tls` jobs succeed. A direct
environment-bound job is required because GitHub did not expose
`admin-tailscale` environment secrets to the previous reusable-workflow call,
even though the manual environment job could use them. Pull requests, forks,
Dependabot, staging, and the public TLS workflow do not join the tailnet.

Its `admin-tailscale` environment must require trusted maintainer approval and
permit only `main`. The production caller explicitly uses `auth_mode: oauth`;
store `TS_OAUTH_CLIENT_ID` and `TS_OAUTH_SECRET` in that environment.
Configure the OAuth client with **Keys > Auth Keys > Write**, restricted to
`tag:github-ci-admin-verify`. Manual runs may select `auth_mode: authkey` and use
the environment's optional `TAILSCALE_AUTH_KEY`, which must be short-lived,
tagged, ephemeral, and pre-approved when required. Each run selects exactly
one mode. The tag cannot administer the tailnet or use broad SSH and may reach
only `tag:admin-sitbank:443`. The admin verification tag cannot reach either
EC2 deployment SSH destination, and the deployment tags cannot reach the
private admin HTTPS destination.

`TAILSCALE_PRIVATE_ADMIN_HOST` in the protected `admin-tailscale` GitHub
Environment is the single workflow source of truth for the private admin
hostname. Both verification jobs consume it; neither keeps a hostname input or
fallback. The current provider value is `admin-sitbank.tailca101b.ts.net`.
`STAGING_EC2_HOST` and `PROD_EC2_HOST` remain separate private SSH deployment
targets, not admin browser targets.

The workflow fails if a `GET` to the private URL responds before enrollment,
then joins the tailnet, requires an unauthenticated `GET` to
`https://${TAILSCALE_PRIVATE_ADMIN_HOST}/login` to return the documented
`200`, and logs out. It checks no admin
credentials, changes no deployment or tailnet state, and enables neither
Tailscale Serve nor Funnel.
Failure marks the post-deploy workflow failed; production may already be
deployed, so operators must investigate rather than rerun deployment blindly.

Rotate OAuth by replacing both OAuth secrets and testing before revoking the
old client. Rotate auth-key mode by replacing `TAILSCALE_AUTH_KEY`, testing,
then revoking the old key. During offboarding, review environment approvers
and branch rules and remove stale CI nodes. To withdraw CI tailnet access,
remove all Tailscale credential secrets, revoke the selected client/key,
remove CI tag grants/devices, and disable or delete the environment. Normal
public TLS scans continue to exclude the private hostname.

This workflow is network-path evidence, not EC2 host-configuration evidence.
The production bootstrap separately installs the non-mutating
`/usr/local/sbin/verify-tailscale-admin-access` preflight. Operators run its
`--mode serve` check on EC2 to inspect the local Tailscale/Funnel state,
loopback listener, Serve mapping, local readiness, Nginx absence, and private
HTTPS response. The host script uses no GitHub secret or Tailscale credential;
normal CI covers its contract with stubs and does not claim to inspect live
Tailscale state. The host verifier derives the local node DNS name from
`tailscale status --json` unless an operator supplies `PRIVATE_ADMIN_HOST`;
that live host discovery does not override the protected environment value
used by workflows.

The separate `ops/tailscale/` host automation installs Tailscale and configures
the production Serve mapping only after explicit operator confirmation. It is
never called by either verification job, pull requests, or normal CI.

## Private Observability Verification

`.github/workflows/observability-private-verify.yml` is manual-only,
`main`-only, read-only, and protected by either `observability-staging` or
`observability-production`. It verifies the private Grafana/Loki deployment
after observability bootstrap, Grafana provisioning, Tailscale ACL/DNS changes,
or operator credential rotation. It is intentionally separate from PR-safe
static tests and from public TLS evidence because Grafana is a private operator
tool and Loki is not Internet-facing.

Configure each protected environment with `GRAFANA_PRIVATE_URL`,
optional `OBSERVABILITY_PUBLIC_PROBE_URLS`, `GRAFANA_HEALTH_TOKEN`,
`TS_OAUTH_CLIENT_ID`, and `TS_OAUTH_SECRET`. The Tailscale OAuth client should
be restricted to `tag:github-ci-observability-verify`, and the Grafana token
must be a least-privilege non-admin health token. Do not store operator
passwords, browser sessions, cookies, MFA values, raw Loki logs, datasource
credentials, or Grafana admin credentials in GitHub.

The workflow checks that private Grafana is unreachable before joining the
tailnet, joins Tailscale, verifies Grafana API health, anonymous API denial,
non-admin verifier role, Loki datasource health, and public denial probes for
`/grafana`, `/loki`, `/logs`, and `/metrics`. It uploads only sanitized JSON
evidence for 30 days and logs out of Tailscale at completion.

## Gitleaks

`.github/workflows/gitleaks.yml` runs Gitleaks 8.30.1 on pull requests and
pushes to `main`, manual dispatches, and a weekly schedule. It checks out full
Git history with `persist-credentials: false`, installs the pinned standalone
CLI after SHA-256 verification, and scans all refs with redacted output. The
workflow has only `contents: read`; it uses no production secrets, uploads no
SARIF or raw report, and does not run deployment commands.

`.gitleaks.toml` extends the built-in rules and has only reviewed rule/path/
line-shape allowlists for confirmed public or synthetic values; historical
exceptions are also commit-bound. It has no baseline. The existing custom
repository secret scanner remains in the main CI and `scripts/ci-local`. See
`docs/security/assurance/secret-scanning.md` for safe local
reproduction, false-positive handling, rotation/revocation, and history-leak
response. After rollout, require `Gitleaks / Full-history secret scan` in
`main` branch protection.

## Repository Static Analysis

Three independent workflows provide early, least-privilege quality and SAST
gates. Each runs on pull requests and pushes to `main`, supports manual reruns,
checks out with `persist-credentials: false`, needs no production secrets or
deployment credentials, and performs no mutating infrastructure operation.

`.github/workflows/shellcheck.yml` downloads checksum-verified ShellCheck
0.11.0 and is the authoritative repository-wide ShellCheck gate. It runs
automatically on pull requests and pushes to `main`; manual dispatch is a
rerun/debug path. `ops/security/discover_lint_targets.py` supplies every tracked `.sh`
file and every tracked file with a supported `sh`/`bash` shebang, including
backup, container, deployment, PostgreSQL, Tailscale, and operational scripts.
Empty discovery fails closed. ShellCheck style, info, warning, and error
findings fail the job. Existing `bash -n` checks remain useful syntax evidence
but are not equivalent to ShellCheck.

The blocking Bandit command scans `app`, `ops`, `config.py`, `wsgi.py`, and
`admin_wsgi.py`, so both customer and admin WSGI entrypoints remain in scope.

`.github/workflows/hadolint.yml` downloads checksum-verified Hadolint 2.14.0
and uses the same helper to find every tracked `Dockerfile` and
`Dockerfile.*`. Empty discovery fails closed and style-or-higher findings fail.
The current Dockerfile has one instruction-scoped `DL3008` exception: the
digest-pinned Debian base must consume supported security-package upgrades
instead of freezing stale package versions.

`.github/workflows/semgrep.yml` runs Semgrep 1.168.0 from an immutable container
digest in local/OSS mode on pull requests, `main` pushes, manual reruns, and a
weekly schedule. It uses the `p/python`, `p/flask`, `p/security-audit`,
`p/owasp-top-ten`, and `p/github-actions` registry packs. Registry rules are
downloaded, but source is scanned locally and is not uploaded to Semgrep.
ERROR severity blocks through `--error`; lower severities remain review
signals during the initial rollout. No Semgrep token, SARIF, artifact, or
`security-events: write` permission is used. Every CI and local invocation
passes `--metrics=off`, so Semgrep metrics are explicitly disabled.

Only virtual environments, caches, coverage/build output, and dependency
directories are excluded. Application, tests, operations, scripts, workflows,
configuration, migrations, templates, Docker/Compose, and deployment-adjacent
files remain in scope where supported. After stable rollout, branch protection
should require `ShellCheck / Repository shell scripts`,
`Hadolint / Repository Dockerfiles`, and `Semgrep / High-severity SAST`.

## DAST Policy

Ordinary pull requests skip the full authenticated ZAP crawl but run the
dedicated `.github/workflows/dast-pr-smoke.yml` check against only a local
ephemeral container. The smoke has a 12-minute command timeout, runs a
two-minute unauthenticated ZAP baseline with selected header rules at `FAIL`,
then exercises a synthetic local session. ZAP `FAIL` alerts and smoke
regressions block; warnings remain report-only. The workflow uploads only a
sanitized summary for seven days. It receives no
deployment/provider credentials and never targets staging, production, or the
private admin hostname.

Authenticated DAST still runs before staging/production deployment during release verification. Manual staging can enable or disable DAST with `run_dast`; scheduled scans keep regular full DAST coverage. This means release verification retains that coverage while PRs stay responsive.

Exact required-check names and the reporting-only status of PR DAST are
recorded in `docs/security/governance/github-branch-protection-evidence.md`.

Synthetic DAST users remain the only authenticated scan identities. The smoke
helper writes the authenticated session cookie and ZAP replacer configuration to
temporary `0600` files created under `umask 077`; the DAST cookie is not passed
as a raw process argument. ZAP loads the authenticated-cookie replacer from a
restricted `-configfile` path, and the cookie/config directory is removed by the
smoke-test cleanup trap on success or failure. Do not upload `auth-cookie` or
`zap-replacer.properties`, do not print environment dumps or shell-expanded
secret values, and investigate immediately if either file or a session value
appears in logs, summaries, or artifacts.

## SonarQube Cloud

The `Test and security checks` job (internal ID `test`) in
`.github/workflows/ci-deploy.yml` runs the complete pytest suite once with
`pytest-cov`, writes `coverage.xml`, and uploads that file as a short-lived
artifact. After it succeeds on pull requests, pushes to `main`, and manual
runs, the downstream `SonarQube analysis` job (internal ID `sonarqube`) calls
the reusable `.github/workflows/sonarqube.yml`. That job checks out the same
immutable source commit, downloads `coverage.xml`, and invokes only the
SHA-pinned official SonarQube scanner; it does not install dependencies, rerun
pytest, or hold any write permission.

The reusable scanner job has only `contents: read`. It requires the GitHub
Actions secret `SONAR_TOKEN`; it does not use production environments,
deployment credentials, or `SONAR_HOST_URL`. Scheduled CI runs skip the
SonarQube job. Coverage retrieval uses the SHA-pinned
`actions/download-artifact` v8.0.1 Node.js 24 action.

The initial SonarQube quality gate is reporting-only and is not a release or
deployment dependency. After a successful trusted internal pull-request scan,
the separate `SonarQube PR comment` job (internal ID `sonarqube-comment`) uses
SHA-pinned, Node.js 24
`actions/github-script` to create or update one informational summary with
workflow and dashboard links. The comment job has only `contents: read` and
`pull-requests: write`; the scanner never receives that write capability. A
hidden marker keeps reruns from creating duplicates.
Fork and Dependabot pull requests receive neither the secret-backed cloud scan
nor the write-permission comment; after safe coverage steps, the workflow emits
a notice explaining the skip. Trusted runs fail clearly if the token is absent.
Inline review comments are intentionally not implemented. Setup, private-project
plan eligibility, source processing, exclusions, rotation, and triage are in
`docs/security/assurance/sonarqube.md`. CodeQL behavior remains unchanged.

## Dependency Updates

Dependabot updates are review-only. Base-image updates must not be auto-merged. For dependency or image changes, maintainers should review release notes, regenerate hash-locked dependency files, and require the container smoke test, Compose validation, Trivy gates, dependency audits, and relevant application tests before merging.

Base image updates must change the pinned Dockerfile digest and the deployment/security test constants in the same reviewed PR.

Treat GitHub Actions runner-runtime deprecation warnings as CI maintenance
issues. Keep JavaScript actions compatible with GitHub's current runner runtime
by replacing deprecated pins with reviewed full commit SHAs; never change them
to floating tags. Runtime updates to the live TLS scan must preserve its
per-target JSON, log, and HTML evidence artifacts, names, failure behavior, and
retention policy.

## SBOM And OpenSSF Scorecard Evidence

`.github/workflows/sbom.yml` generates
`sitbank-source-sbom-cyclonedx.json` with pinned Syft 1.46.0 from `dir:.` on
pull requests to `main`, pushes to `main`, and manual dispatch. It uploads only
the `sitbank-source-sbom` CycloneDX JSON artifact for 30 days with
`contents: read` and checkout credentials disabled. Generated SBOM files are
evidence artifacts and must not be committed.

This source artifact complements the existing Docker Buildx `sbom: true`
release-image attestation. An explicit image SBOM artifact remains deferred
until the exact digest-verified release image can be supplied to Syft without
adding registry write privileges or untrusted-PR credentials. SBOM generation
is inventory evidence, not vulnerability scanning; dependency audit and Trivy
remain separate controls.

`.github/workflows/scorecard.yml` runs the official SHA-pinned OpenSSF
Scorecard action on pushes to `main`, weekly, and by manual dispatch. It is
informational and not a required pull-request check. The workflow keeps
`contents: read`, publishes no result to the public Scorecard service, grants
neither `id-token: write` nor `security-events: write`, and retains the
`openssf-scorecard-results` SARIF artifact for 30 days. Record the numeric
baseline and key findings after the first merged run; until then the Dependency
Review observations are the qualitative baseline and no numeric score is
claimed.
