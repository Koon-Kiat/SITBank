# GitHub Actions

## Release Flow

The normal release path is:

```text
main push -> publish -> release-verify -> staging -> production
```

The tested, scanned, signed, and deployed digest must be identical. Deployments never use `latest`.

Production never skips disabled, skipped, or failed staging. It runs only after
release verification and staging deployment both succeed on `main`, with
`PROD_DEPLOY_ENABLED = true` and GitHub production environment approval.

## Manual Pre-Merge Staging

Manual pre-merge staging:

1. run trusted workflow from main;
2. set `source_ref = candidate branch, tag, or SHA`;
3. resolve immutable source_sha;
4. build, test, scan, sign, and verify the candidate image;
5. deploy staging using trusted main scripts.

Feature-branch workflow and deployment scripts are never executed with environment secrets. The only accepted migration mode for existing EC2 deployment files is `adopt-existing`, and it must still pass wrapper hash validation before app deployment.

The SSH deployment jobs assume the configured EC2 deploy user is reachable from
an approved source. GitHub-hosted runners do not have stable source IPs, so
repo-side SSH hardening is deferred to avoid accidentally breaking
deployment. Move deployment behind an allowlisted self-hosted runner, bastion,
VPN egress, or OIDC plus AWS Systems Manager only in a separate reviewed change
that tests rollback and GitHub Actions reachability.

## Environment Variables

GitHub environment variables provide only non-secret deployment settings. Keep
`STAGING_DEPLOY_ENABLED` and `PROD_DEPLOY_ENABLED` as repository variables. Put
environment-specific settings, including SMTP sender/host values, under their
matching GitHub environment. For both `staging` and `production`, set:

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
- `ROOT_ADMIN_EMAILS`

`ROOT_ADMIN_EMAILS` is scoped by GitHub environment rather than prefix: set it
separately in both the `staging` and `production` environments. It must be a
comma-separated list of exactly 7 SIT workplace email addresses. The deployment
workflow maps it into the prefixed renderer input for the target environment
and writes `ROOT_ADMIN_EMAILS` into the signed runtime `container.env`.

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

`<PREFIX>_MFA_KEK_ACTIVE_ID` must match a key identifier in the root-managed `/etc/sitbank*/secrets/mfa_kek_keys_json` file on EC2. Do not put `MFA_KEK_KEYS_JSON` in GitHub Actions; the KEK keyring is a long-lived secret and remains host-managed.
`<PREFIX>_ADMIN_SESSION_HMAC_ACTIVE_KEY_ID` must match a key identifier in
`/etc/sitbank*/secrets/admin_session_hmac_keys_json`. Do not put admin Flask,
CSRF, session-HMAC, session-lookup HMAC, password-pepper, or database secret values in GitHub
Actions; those remain root-managed EC2 secret files.
`SECURITY_AUDIT_HMAC_KEY` is also a root-managed EC2 secret file and is not
exported through GitHub Actions environment variables.
Do not pass root-admin passwords, TOTP secrets, QR codes, provisioning URIs, or
TOTP setup values through GitHub Actions. Root-admin bootstrap remains a manual
operator command run over SSH inside the private admin container after
deployment.

## Private Tailnet Verification

`.github/workflows/tailscale-private-admin-verify.yml` is a separate manual
workflow. It is the only GitHub-hosted job permitted to join the tailnet and
is not called by pull-request, deployment, or public TLS workflows.
Its `tailscale-private-admin-verification` environment must require trusted
maintainer approval, permit only `main`, and hold the sole
`TAILSCALE_AUTH_KEY` secret. Configure that key as reusable, ephemeral,
pre-approved when needed, tagged, and limited to the private admin HTTPS
service.

The workflow fails if the private URL responds before enrollment, then joins
the tailnet, requires `https://sitbank-admin.tailca101b.ts.net/login` to return
the documented unauthenticated `200`, requires the public customer
`https://sitbank.duckdns.org/admin` route to remain denied with `404`, and logs
out. It checks no admin credentials, changes no deployment or tailnet state,
and enables neither Tailscale Serve nor Funnel.

Rotate the environment secret with a replacement key and one approved `main`
test before revoking the old key. During offboarding, review environment
approvers and branch rules and remove stale CI nodes. To withdraw CI tailnet
access, remove the secret, revoke the key, remove the CI tag grants/devices,
and disable or delete the environment. Normal public TLS scans continue to
exclude the private hostname.

## DAST Policy

Ordinary pull requests skip the full authenticated DAST crawl to keep feedback fast. They still run unit tests, compile checks, `pip check`, Bandit, dependency audits, dependency lock validation, repository secret scan, Docker image build, container smoke test, Compose validation, and Trivy gates.

Authenticated DAST still runs before staging/production deployment during release verification. Manual staging can enable or disable DAST with `run_dast`; scheduled scans keep regular full DAST coverage. This means release verification retains that coverage while PRs stay responsive.

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

The `test` job in `.github/workflows/ci-deploy.yml` runs the complete pytest
suite once with `pytest-cov`, writes `coverage.xml`, and uploads that file as a
short-lived artifact. After the test job succeeds on pull requests, pushes to
`main`, and manual runs, the downstream `sonarqube` job calls the reusable
`.github/workflows/sonarqube.yml`. That job checks out the same immutable
source commit, downloads `coverage.xml`, and invokes only the SHA-pinned
official SonarQube scanner; it does not install dependencies, rerun pytest, or
hold any write permission.

The reusable scanner job has only `contents: read`. It requires the GitHub
Actions secret `SONAR_TOKEN`; it does not use production environments,
deployment credentials, or `SONAR_HOST_URL`. Scheduled CI runs skip the
SonarQube job. Coverage retrieval uses the SHA-pinned
`actions/download-artifact` v8.0.1 Node.js 24 action.

The initial SonarQube quality gate is reporting-only and is not a release or
deployment dependency. After a successful trusted internal pull-request scan,
the separate `sonarqube-comment` job uses SHA-pinned, Node.js 24
`actions/github-script` to create or update one informational summary with
workflow and dashboard links. The comment job has only `contents: read` and
`pull-requests: write`; the scanner never receives that write capability. A
hidden marker keeps reruns from creating duplicates.
Fork and Dependabot pull requests receive neither the secret-backed cloud scan
nor the write-permission comment; after safe coverage steps, the workflow emits
a notice explaining the skip. Trusted runs fail clearly if the token is absent.
Inline review comments are intentionally not implemented. Setup, private-project
plan eligibility, source processing, exclusions, rotation, and triage are in
`docs/security/sonarqube.md`. CodeQL behavior remains unchanged.

## Dependency Updates

Dependabot updates are review-only. Base-image updates must not be auto-merged. For dependency or image changes, maintainers should review release notes, regenerate hash-locked dependency files, and require the container smoke test, Compose validation, Trivy gates, dependency audits, and relevant application tests before merging.

Base image updates must change the pinned Dockerfile digest and the deployment/security test constants in the same reviewed PR.

Treat GitHub Actions runner-runtime deprecation warnings as CI maintenance
issues. Keep JavaScript actions compatible with GitHub's current runner runtime
by replacing deprecated pins with reviewed full commit SHAs; never change them
to floating tags. Runtime updates to the live TLS scan must preserve its
per-target JSON, log, and HTML evidence artifacts, names, failure behavior, and
retention policy.
