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
repo-side Issue 186 SSH hardening is deferred to avoid accidentally breaking
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

## DAST Policy

Ordinary pull requests skip the full authenticated DAST crawl to keep feedback fast. They still run unit tests, compile checks, `pip check`, Bandit, dependency audits, dependency lock validation, repository secret scan, Docker image build, container smoke test, Compose validation, and Trivy gates.

Authenticated DAST still runs before staging/production deployment during release verification. Manual staging can enable or disable DAST with `run_dast`; scheduled scans keep regular full DAST coverage. This means release verification retains that coverage while PRs stay responsive.

## Dependency Updates

Dependabot updates are review-only. Base-image updates must not be auto-merged. For dependency or image changes, maintainers should review release notes, regenerate hash-locked dependency files, and require the container smoke test, Compose validation, Trivy gates, dependency audits, and relevant application tests before merging.

Base image updates must change the pinned Dockerfile digest and the deployment/security test constants in the same reviewed PR.

Treat GitHub Actions runner-runtime deprecation warnings as CI maintenance
issues. Keep JavaScript actions compatible with GitHub's current runner runtime
by replacing deprecated pins with reviewed full commit SHAs; never change them
to floating tags. Runtime updates to the live TLS scan must preserve its
per-target JSON, log, and HTML evidence artifacts, names, failure behavior, and
retention policy.
