# Deployment Rules for SITBank Agents

Use these rules when changing deployment scripts, GitHub Actions, EC2 bootstrap, Docker/Compose, Nginx, Cloudflare, Tailscale, TLS, database migrations, provider verification, or production/staging workflows.

These rules are standing policy. When drafting GitHub issues, include only deployment impacts and guardrails that are specific to the issue. Do not paste this whole checklist into issue bodies.

## Source-of-truth before deployment guidance

Before writing a deployment-related issue or recommendation, inspect the latest available repository state.

Preferred order:

- Use the GitHub connector for latest committed repository state when available.
- Use an uploaded zip, branch snapshot, or exact files for uncommitted/local/private-branch state.
- Ask for the latest repo snapshot or exact files when repository state is unavailable or ambiguous.

Do not assume deployment scripts, workflow names, Nginx templates, ports, hostnames, or environment variables from memory.

## Core deployment principles

Deployment changes must be safe, explicit, observable, and reversible.

Preserve:

- Trusted bootstrap verification.
- Cosign certificate identity checks.
- Staging-first production deployment.
- GitHub Environment approvals for production where intended.
- Protected environments for sensitive verification credentials.
- Least-privilege workflow permissions.
- No secret exposure to untrusted PRs.
- Rollback behavior.
- Readiness checks that match the actual security boundary.
- Separation between customer app and admin app deployment units.
- Safe provider-state evidence.

Do not weaken a deployment guard to make a deploy pass.

## Bootstrap and trusted artifact rules

Do not weaken certificate identity checks.

When the repository owner/name changes, update trusted host config explicitly instead of allowing both old and new identities broadly.

Expected trusted config files may include:

- `/etc/sitbank-staging/deploy.conf`
- `/etc/sitbank/deploy.conf`

These configs should use the current trusted repository and GHCR identity.

Do not use broad certificate identity regexes, accept artifacts from untrusted workflows/branches/repos, bypass cosign verification, allow multiple repo identities as a shortcut, or replace fail-closed verification with warnings only.

Trusted bootstrap or deploy wrapper changes usually require EC2 bootstrap before the host can use the updated wrapper.

## GitHub Actions rules

Workflow permissions must be least privilege. Use `contents: read` unless a workflow needs additional permissions, and document any additional permission.

Avoid:

- `pull_request_target` for workflows handling untrusted code.
- Production secrets in PR workflows.
- Cloudflare/Tailscale/AWS credentials in untrusted PR workflows.
- Environment dumps.
- Raw provider response artifacts.
- Broad write permissions.
- Deploying unreviewed PR code to production.

Pin third-party actions according to the repo policy.

Security workflows should not upload raw secret findings unless they are sanitized.

Workflows that build, sign, publish, or deploy artifacts must preserve artifact integrity, provenance, expected branch/workflow identity, and least-privilege permissions.

## Branch protection and required checks

Repo files cannot prove GitHub branch protection by themselves.

Document expected provider-side settings and required checks.

For PRs, require checks that actually run on PRs. Do not require staging or production deployment before PR merge unless PRs actually deploy to those environments and the security model approves that.

Recommended flow:

```text
PR -> CI/security/status checks -> review approval -> merge to main
main -> build/publish -> deploy staging -> verify staging -> environment-approved production
```

SonarQube should not be required until CI-based analysis is stable, Automatic Analysis is disabled, coverage imports correctly, and quality gate behavior is confirmed.

## Staging deployment rules

Staging should preserve:

- Cloudflare Access as identity-aware boundary.
- Cloudflare Authenticated Origin Pull as origin-bypass protection.
- Nginx rate limits and security headers.
- Loopback-only readiness where intended.
- Flask login/MFA/CSRF/session/authorization after Cloudflare Access.
- Direct-origin fail-closed behavior.

Staging readiness must not rely on public `/health/ready` when that endpoint is intentionally blocked by Cloudflare/Nginx origin protection.

Use local readiness from the host, such as `http://127.0.0.1:8081/health/ready`, or the repo-approved local readiness endpoint.

Public `/health/ready` should remain unavailable if that is the selected staging contract.

Direct-origin staging requests must fail closed and must not return SITBank app content. Accepted fail-closed outcomes may include `400`, `403`, TLS client-certificate failure, or connection rejection. Do not require exact `403` unless the design guarantees exact `403`.

## Production deployment rules

Production deployment should remain protected by staging-first deployment, production preflight checks, production GitHub Environment approval where intended, cosign signature verification, expected certificate identity, release verification, TLS verification, private admin post-deploy verification where configured, and rollback on failed deploy/readiness.

Do not convert production to manual-only unless explicitly requested, deploy to production from PRs, skip staging verification before production without approval, reuse staging secrets for production, or weaken production preflight checks to work around missing configuration.

## Nginx rules

Preserve unknown-host denial, TLS policy includes, `server_tokens off`, security headers, rate limits, hidden/sensitive file denial, loopback upstreams, Cloudflare Authenticated Origin Pull where configured, public admin denial, and location-level enforcement for proxied routes.

Do not expose admin app publicly or expose staging app directly to origin bypass.

When adding a new Nginx location with `proxy_pass`, add tests proving the required boundary is still enforced. Do not move security headers, auth checks, or origin protection into locations in a way that creates bypasses for sibling locations.

## Cloudflare rules

Cloudflare Access and provider state are external and must be verified through safe evidence. Do not claim repo files alone prove live provider state.

Provider evidence must be sanitized and must not include Cloudflare API tokens, Access service tokens, JWTs, cookies, raw Access assertions, OAuth secrets, private keys, or raw provider exports containing sensitive values.

Cloudflare verification should fail closed if policy is missing, broad, or misconfigured, and should not mutate provider state unless the workflow is explicitly a provisioning workflow.

Preserve Cloudflare Access policy intent, MFA/IdP requirements where configured, Authenticated Origin Pull, and direct-origin fail-closed behavior.

## Tailscale rules

Private admin access through Tailscale must remain private.

Preserve protected GitHub Environment for tailnet verification secrets, Tailscale Serve only to the loopback admin port, Funnel disabled, Tailscale SSH disabled unless approved, public non-reachability checks for admin hostname, logout/cleanup after CI verification, and admin app isolation from public customer/staging routes.

Do not expose admin UI through public Cloudflare/Nginx customer or staging routes.

Do not claim Tailscale provider or ACL state is proven by committed docs alone.

## Docker and Compose rules

Preserve non-root containers where configured, loopback host port bindings, health checks, secret-file usage, production/staging Compose separation, image signing/provenance/SBOM behavior, admin/customer runtime separation, and least-privilege database/runtime roles.

Do not print secrets from Compose env files or secret files.

Do not push images from untrusted PRs.

Do not relax container hardening, health checks, or network isolation without explicit issue requirements and replacement tests.

## Database migration rules

Deployment issues involving migrations must specify whether a migration is required, whether staging and production migrations are required, rollback/downgrade behavior, model/migration consistency, runtime role or grants changes, and backup/manual recovery impact.

Do not hide migration impact.

Use dialect-portable Alembic patterns where tests use SQLite and production uses PostgreSQL.

## Secrets and environment rules

Deployment changes involving secrets or environment variables must specify which environment variables or secret files are added, removed, or renamed, whether staging/production/admin/customer runtime configs are affected, whether GitHub Environment secrets need updates, whether EC2 root-owned config files need updates, and whether provider-side secrets need review.

Do not print secrets, env files, tokens, cookies, provider exports, or private keys in CI output, docs, screenshots, or artifacts.

## Manual verification rules

Deployment issues should include manual verification when provider or host state is involved, such as `sudo nginx -t`, local readiness curl, direct-origin fail-closed curl, Cloudflare Access verification, Tailscale private admin verification, TLS evidence, service health, cosign identity output without secrets, or GitHub Environment/protection evidence without secrets.

Do not paste secrets, tokens, private keys, cookies, service tokens, or raw provider exports into issues, PRs, logs, screenshots, or artifacts.

## Deployment impact in generated issues

Use compact deployment impact in generated issues.

For no-impact issues, prefer:

```text
Deployment impact: no EC2 bootstrap, staging/prod deploy, database migration, secret change, or provider setting change expected.
```

For deployment issues, list only relevant changed or review-required items:

- EC2 bootstrap required.
- Staging deployment required.
- Production deployment required.
- Database migration required.
- Application secrets changed.
- GitHub Environment settings review required.
- Cloudflare/Tailscale provider settings review required.
- Manual verification required.
- Rollback behavior changed.

Do not include a long matrix of “no” values unless the user asks for it.

## Validation commands

Always include:

```powershell
git diff --check
.\.venv\Scripts\python.exe -m pytest -q -n auto
```

If coverage-relevant code or test structure changes, generate coverage for SonarQube/SonarCloud import and ensure coverage remains at least 90% without weakening the quality gate.
