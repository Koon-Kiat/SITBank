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
- Do not expose authentication secrets or one-time values, including passwords, tokens, cookies, session IDs, CSRF values, TOTP/recovery codes, or WebAuthn challenges and assertions.
- Keep cryptographic keys, database connection values, mail-provider credentials, infrastructure exports, SSH keys, and real customer data out of logs, commits, uploads, and responses.

## Commit and pull request authorship

- Do not add Claude, Anthropic, or any AI tool as a commit author, co-author, or trailer. Do not append `Co-Authored-By: Claude ...` or similar attribution lines to commit messages.
- Do not add AI tool attribution such as `Generated with Claude Code` to commit messages or pull request bodies.
- Write commit and pull request text as the human contributor's own work, following `docs/CONTRIBUTION_MESSAGE_POLICY.md`.

## Pull request description formatting

- Write each pull request description paragraph as a single continuous line. Do not hard-wrap description prose onto multiple physical lines at a fixed column; let it soft-wrap when rendered.
- Keep each Setext section body flowing directly under its heading. Do not break a sentence or clause onto a new line by itself.
- Example: write `Restores the TOTP replay handling and the stuck setup_pending resend recovery path that PR #544 dropped, relocates the no-AI-authorship rule, and raises the MFA wrong-code thresholds.` as one line, not split across several wrapped lines.
- This applies to pull request descriptions only. Commit message bodies still wrap normally.

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
