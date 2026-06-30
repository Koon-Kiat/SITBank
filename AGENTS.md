# AGENTS.md

This file defines the working rules for AI coding agents, Codex, ChatGPT, and contributors working in this repository.

These instructions apply to the whole SITBank repository unless a more specific `AGENTS.md` exists in a subdirectory.

## Project priorities

SITBank is a secure software development banking application. Treat security, correctness, auditability, and deployment safety as first-class requirements.

Preserve or improve:

- Customer, staff, admin, and root-admin identity separation.
- Flask authentication, MFA, CSRF, session controls, authorization, audit logging, and alerting.
- Customer/admin deployment isolation.
- Staging Cloudflare Access and Authenticated Origin Pull boundaries.
- Private admin access through Tailscale or another explicitly approved private-access control.
- CI/CD security gates, artifact signing, provenance, SBOM, and required evidence.
- PR creation, branch, commit, and push workflows that require explicit user authorization.
- Documentation accuracy and stale-documentation checks.

Do not weaken an existing security control to make a test pass unless the issue explicitly asks for that design change and the replacement control is documented, tested, and at least as secure.

## Source-of-truth and repository state

Use the latest available source of truth before creating repo-specific implementation guidance.

Preferred order:

- Inspect the latest committed repository state through the GitHub connector when GitHub access is available.
- Use an uploaded repository zip, branch snapshot, or exact files when the user is asking about uncommitted local changes, a private branch not accessible through GitHub, a comparison between snapshots, or an exact archived state.
- Ask for a repo zip or exact files when GitHub access is unavailable, stale, ambiguous, or insufficient for the requested analysis.

Do not assume the current code state from memory. Treat prior chat context as helpful background only, not proof of the current repository state.

## GitHub issue workflow

When creating or updating GitHub issues for this repo, follow `docs/codex/github-issue-rules.md`.

Important defaults:

- Draft in chat by default.
- Create, update, close, label, or comment on GitHub only when the user explicitly asks for that GitHub action.
- Search existing open and recently closed issues for duplicates or near-duplicates before creating a new GitHub issue when GitHub access is available.
- Write one integrated GitHub issue that a contributor can copy directly and use as the implementation prompt.
- Put the title in the GitHub title field only. The issue body starts at `## Summary` and must not repeat `# Title`.
- Keep issues concise and focused.
- Do not copy generic rules from this file or `docs/codex/*.md` into every issue. These files are standing policy, not issue-body text.
- Include issue-specific implementation, tests, documentation updates, validation commands, acceptance criteria, and deployment impact when relevant.
- Use hyphen bullets, not asterisk bullets.

## GitHub branch, commit, and PR workflow

When implementing issues, creating branches, committing changes, pushing branches, or opening pull requests for this repo, follow `docs/codex/github-pr-rules.md`.

Important defaults:

- Do not create branches, commit, push, or open pull requests unless the user explicitly asks for implementation work that includes those actions.
- When the user explicitly asks for the full PR workflow, create a branch, commit the intended changes, push the branch, and open a pull request when tool access is available.
- Use the repository PR template when opening a pull request.
- Never push directly to protected branches.
- Never auto-merge a pull request.
- Review the diff before committing and avoid staging unrelated files, generated artifacts, secrets, provider exports, local environment files, or caches.
- Report validation honestly; do not claim tests passed if they were not run.

## Issue anti-inflation rule

Generated issue bodies should be as short as safely possible.

Default issue body sections:

- `## Summary`
- `## Required implementation`
- `## Tests to add or update`
- `## Documentation updates`
- `## Validation commands`
- `## Acceptance criteria`
- `## Deployment impact` only when relevant

Omit these unless they add issue-specific value:

- `## Goal`
- `## Completion checklist`
- Long security checklists
- Long deployment checklists
- Long documentation-file inventories
- Long lists of unrelated controls that must be preserved
- Long SonarQube/SonarCloud boilerplate

For high-risk security, deployment, authentication, authorization, cryptography, Cloudflare, Tailscale, Nginx, CI/CD, or production-guard issues, include enough guardrails to avoid weakening existing controls, but keep them specific to the issue.

## Required workflow

Before changing code:

- Read the issue completely.
- Identify the security, privacy, deployment, or data boundary the issue touches.
- Inspect the current repository state using the source-of-truth rules above.
- Search for existing tests and docs covering that boundary.
- Prefer small, focused changes over broad rewrites.
- Keep backwards compatibility unless the issue explicitly asks for a breaking migration.

When changing code:

- Add or update tests in the same change.
- Add or update documentation in the same change.
- Add or update stale-doc checks where a fix changes a documented security status.
- Keep logs, audit metadata, CI output, and generated artifacts sanitized.
- Avoid production secrets, real tokens, real keys, real JWTs, real customer data, real emails, or real infrastructure credentials in tests or docs.

Before finishing:

```powershell
git diff --check
.\.venv\Scripts\python.exe -m pytest -q -n auto
```

If coverage-relevant source code, workflow tests, documentation checks, or test structure changed, also run the project coverage command that generates `coverage.xml` for SonarQube/SonarCloud import.

Ensure total coverage remains at least 90% and do not weaken the SonarQube/SonarCloud quality gate.

## Security engineering rules

Follow `docs/codex/security-rules.md` for security-sensitive code, tests, docs, deployment, and operations changes.

Key principles:

- Defense in depth.
- Least privilege.
- Secure defaults.
- Complete mediation.
- Fail closed.
- Separation of duties.
- Safe auditability.
- Secret minimization.
- Explicit trust boundaries.
- Privacy-preserving logging.
- Configuration validation before readiness.

Never commit, log, print, or upload real secrets, credentials, tokens, cookies, JWTs, keys, session IDs, CSRF tokens, TOTP material, recovery codes, WebAuthn challenge/assertion material, database URLs, SMTP credentials, provider exports, or real customer data.

Use fake values in tests and documentation. Fake values must be clearly fake.

## Deployment and operations rules

Follow `docs/codex/deployment-rules.md` when touching deployment, bootstrap, Nginx, Cloudflare, Tailscale, GitHub Actions, environments, Docker/Compose, TLS, migrations, or production/staging workflows.

Do not weaken:

- Cosign certificate identity checks.
- Trusted bootstrap/deploy wrapper verification.
- GitHub Environment protections.
- Staging-first production deployment gates.
- Cloudflare Access or Authenticated Origin Pull.
- Tailscale private admin access.
- Loopback-only health/readiness assumptions.
- Direct-origin fail-closed behavior.
- Rollback behavior.
- Least-privilege workflow permissions.

Staging readiness must use local readiness, not public `/health/ready`, when Cloudflare origin protection intentionally blocks public readiness.

## Coding style

- Prefer clear, explicit names over clever abstractions.
- Keep security-sensitive helpers centralized.
- Avoid duplicating policy logic across app, admin app, deployment scripts, workflows, and tests.
- Prefer allowlists over denylists for privileged identities and trusted origins.
- Fail with safe, actionable errors.
- Keep user-facing errors generic where detailed security internals would help attackers.
- Keep audit events specific enough for accountability while redacting sensitive values.
- Keep generated files out of version control unless the issue explicitly says to commit them.

## If unsure

If a requested change appears to weaken security, stop and explain the risk in the PR or issue before implementing. Prefer documenting a safer alternative with tests.
