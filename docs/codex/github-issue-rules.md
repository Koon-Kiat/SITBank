# GitHub Issue Rules for SITBank

Use this file when drafting, updating, or creating GitHub issues for SITBank.

This file is standing policy. Do not paste this file into generated issue bodies.

## Source-of-truth before drafting

Before creating a repo-specific issue, inspect the latest available repository state.

Preferred order:

- Use the GitHub connector to inspect the latest committed `Koon-Kiat/SITBank` repository state when GitHub access is available.
- Use an uploaded repo zip, branch snapshot, or exact files when the user is asking about uncommitted local changes, a private branch, a comparison between snapshots, or an exact archived state.
- Ask the user for a zip or exact files when GitHub access is unavailable, stale, ambiguous, or insufficient.

Do not assume current code state from memory, prior chats, old zip files, or stale analysis.

Use uploaded repo snapshots only as private reference. Do not paste broad repo-background into the issue unless it is needed to explain the specific task.

## GitHub write-action rules

Draft in chat by default.

Create, update, close, label, or comment on GitHub issues only when the user explicitly asks for that GitHub action.

Examples that allow GitHub issue creation:

- “Create this as a GitHub issue in `Koon-Kiat/SITBank`.”
- “Open this issue on GitHub.”
- “Create the GitHub issue now.”

Examples that do not allow GitHub write actions:

- “Create an issue here.”
- “Draft an issue.”
- “Give me a GitHub issue.”
- “Do not create on GitHub.”

When GitHub issue creation is explicitly requested and GitHub access is available:

- Search existing open and recently closed issues for duplicates or near-duplicates.
- If an overlapping issue exists, explain the overlap and ask whether to reuse, update, or create a narrowly scoped follow-up.
- Create one issue only unless the user asks for multiple issues.
- Keep labels precise and useful. Do not over-label.
- After creating the issue, return the issue title and URL.

## Issue relationship guidance

When creating, updating, or reviewing SITBank issues, identify whether GitHub-native issue relationships would help the user manually organize the work.

After the issue action or draft, inform the user when any of these four manual relationships are appropriate:

- Parent or sub-issue: use when one issue is a clearly narrower part of a broader tracker.
- Blocked by: use when an issue cannot be completed safely until another issue is finished.
- Blocking: use when the current issue must be completed before another issue can proceed.
- Security alert: use only when the issue directly corresponds to a real GitHub security alert, such as CodeQL, Dependabot, or secret scanning.

Do not create relationship comments, parent/child comments, or backlinks unless the user explicitly asks for comments. Prefer concise manual instructions such as:

```text
Manual relationship to set:
- Set #301 parent to #223.
- Set #299 as blocked by #295 only if #295 must close before #299 can close.
- Add security alert only if the issue maps to an actual GitHub security alert.
```

Do not force relationships. If issues are only loosely related, say they can remain unlinked.


## Core format

Write every issue as one integrated GitHub issue that a contributor can copy directly and use as the implementation prompt.

Use the GitHub title field for the title. The issue description/body must start with `## Summary` and must not include `# Title`.

Do not include:

- A separate “prompt” section.
- A separate “implementation prompt” section.
- A “ChatGPT instructions” section.
- A Codex-only section.
- A repo-background section such as “Current repo context” unless the user explicitly asks for it.

Use hyphen bullets only. Do not use asterisk bullets.

Keep issues concise and focused. Rely on `AGENTS.md` and `docs/codex/*.md` as standing rules; do not repeat their generic boilerplate unless it is directly relevant to the issue.

## Anti-inflation rules

Generated issues should include the minimum sections needed for a contributor to implement and verify the change safely.

Default sections:

- `## Summary`
- `## Required implementation`
- `## Tests to add or update`
- `## Documentation updates`
- `## Validation commands`
- `## Acceptance criteria`
- `## Deployment impact` only when relevant

Omit by default:

- `## Goal` when it repeats the summary.
- `## Completion checklist` when it repeats acceptance criteria.
- Large “review at least these docs” inventories.
- Large “preserve all existing scanners/checks” inventories.
- Large “do not use these secrets” inventories.
- Large deployment impact matrices where every answer is “no”.
- Long SonarQube/SonarCloud text when one short coverage bullet is enough.
- Optional local commands that are not required to close the issue.

Suggested length targets:

- Low-risk docs/test/maintenance issue: 200–450 words.
- Normal source or workflow issue: 350–750 words.
- High-risk security/deployment issue: 700–1,200 words only when necessary.

Do not force these limits when the issue truly needs more detail, but first remove repeated standing policy, unrelated controls, and duplicate acceptance/checklist items.

## What to include

Good issues should include issue-specific content only:

- What needs to change.
- What tests need to prove.
- What docs need to change.
- What validation commands must run.
- What acceptance criteria close the issue.
- What deployment, migration, secret, or provider impact exists when relevant.
- What security guardrails are specific to the touched boundary.

Avoid vague phrases like “improve security” without defining the control and expected tests.

## Tests section rules

Keep tests focused. Prefer 3–7 issue-specific bullets.

Include:

- Positive behavior when useful.
- Negative/fail-closed or bypass behavior when relevant.
- Static workflow/config checks when changing CI or deployment.
- Documentation consistency checks when docs could become stale.

Do not paste full generic security testing checklists. Do not repeat “do not require live Cloudflare/Tailscale/AWS/etc.” unless the issue could accidentally add those dependencies.

## Documentation section rules

Always include documentation updates inside the issue.

Keep this section targeted:

- Name specific docs only when the affected docs are known.
- Otherwise say “Update the docs that currently mention this behavior or gap.”
- Do not list every possible repo doc for every issue.
- Include a stale-doc consistency check only when docs could keep claiming the old state.

## Security guardrail rules

For security issues, include only guardrails relevant to the boundary being changed.

Useful guardrails may state:

- What fails closed.
- What is allowed.
- What is rejected.
- What must not be logged or committed.
- What existing control must not be weakened.
- What tests prove the boundary.

Do not paste the full `security-rules.md` checklist into the issue.

## Deployment impact rules

Include deployment impact only when relevant.

For no-impact issues, prefer one compact line:

```text
Deployment impact: no EC2 bootstrap, staging/prod deploy, database migration, secret change, or provider setting change expected.
```

For deployment issues, list only the changed or review-required items. Do not include a long matrix of “no” values unless the user asks for it.

## SonarQube / SonarCloud coverage rules

Mention SonarQube/SonarCloud only when the issue changes source code, tests, workflow tests, documentation checks, CI paths, source paths, or coverage-relevant behavior.

Keep it short. Usually this is enough:

- Add/update tests for changed behavior and ensure coverage remains at least 90% without weakening the quality gate.

Include the coverage command only when coverage generation or coverage config is directly relevant:

```powershell
.\.venv\Scripts\python.exe -m pytest -q -n auto --cov=. --cov-config=.coveragerc --cov-report=xml:coverage.xml --cov-report=term
```

Do not include long generic SonarQube boilerplate for docs-only or simple workflow-evidence issues.

## Validation commands

Always include:

```powershell
git diff --check
.\.venv\Scripts\python.exe -m pytest -q -n auto
```

Add targeted tests before the full suite only when a likely target file is known.

Do not add optional local tooling commands unless they are required or the user asks for them.

## Avoid overclaiming

Do not claim:

- GitHub branch protection is enforced by repo files alone.
- CODEOWNERS is enforced unless branch protection requires Code Owner review.
- Cloudflare Access provider state is proven by committed config alone.
- Tailscale ACL/provider state is proven by docs alone.
- SonarQube is stable until CI analysis passes and coverage imports correctly.
- Hostname-scoped Authenticated Origin Pull is implemented unless provider-side config, Nginx, tests, and docs support it.

## Labels

Do not over-label issues. Labels should be precise and useful for triage. Avoid applying every broad security/domain label to every issue.

## Relationship to PR workflow rules

Issue drafting and creation rules are separate from implementation and PR workflow rules. For implementation work, branch creation, commits, pushes, and pull requests, follow `docs/codex/github-pr-rules.md`. Do not include PR workflow boilerplate inside issue bodies unless the issue specifically changes that workflow.
