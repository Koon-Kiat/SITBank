@AGENTS.md
@docs/codex/github-issue-rules.md
@docs/codex/github-pr-rules.md
@docs/codex/security-rules.md
@docs/codex/deployment-rules.md

# Claude instructions for SITBank

Use the imported files above as standing project rules for all SITBank work.

## Repository behavior

- Treat the current repository files as the source of truth.
- Do not assume old zip uploads, old chat context, or stale documentation are current when repository files disagree.
- For security, deployment, authentication, authorization, cryptography, Cloudflare, Tailscale, Nginx, CI/CD, and production-guard work, preserve existing controls unless a reviewed issue explicitly requires a change.
- Do not log, print, commit, upload, or expose secrets, tokens, cookies, session IDs, CSRF values, TOTP/recovery/WebAuthn material, HMAC/encryption keys, database URLs, SMTP credentials, provider exports, SSH keys, or real customer data.

## GitHub issues

When creating GitHub issues:

- Draft in chat unless the user explicitly asks you to create the issue on GitHub.
- Search existing open and recently closed issues first when GitHub access is available.
- Write one integrated GitHub issue that can be copied directly as the implementation prompt.
- Start the issue body with `## Summary`.
- Keep the issue concise and focused.
- Use hyphen bullets.
- Include documentation updates.
- Include documentation consistency tests/checks when relevant.
- Include SonarQube/SonarCloud coverage expectations only when the issue changes source code, tests, CI, workflow paths, or coverage-relevant behavior.
- Always include this validation command:

```powershell
.\.venv\Scripts\python.exe -m pytest -q -n auto
```

## Validation baseline

Prefer these validation commands for code or test changes:

```powershell
git diff --check
.\.venv\Scripts\python.exe -m pytest -q -n auto
```

For coverage-relevant changes, also include:

```powershell
.\.venv\Scripts\python.exe -m pytest -q -n auto --cov=. --cov-config=.coveragerc --cov-report=xml:coverage.xml --cov-report=term
```

Do not reduce existing coverage or weaken the quality gate.
