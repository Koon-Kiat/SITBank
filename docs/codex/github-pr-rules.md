# GitHub Pull Request Rules for SITBank

Use this file when implementing issues, committing changes, pushing branches, or opening pull requests for SITBank.

This file is standing policy. Do not paste this whole file into PR bodies or issue bodies.

## Explicit write-action rule

Do not create branches, commit, push, or open pull requests unless the user explicitly asks for implementation work that includes those actions.

Examples that allow the full PR workflow:

- "Implement this issue and open a PR."
- "Create a branch, commit the changes, push it, and open a PR."
- "Fix issue #123 and create a PR."
- "Use Codex to implement this and submit a PR."

Examples that do not allow repository write actions:

- "Draft a PR description."
- "Create an issue."
- "What should we change?"
- "Review this code."
- "Give me a prompt."

When the user explicitly requests the full PR workflow and tool access is available, complete it without asking repeated confirmation unless a safety, ambiguity, credential, branch, or test failure issue requires user choice.

The full PR workflow means:

- Create a branch.
- Commit the intended changes.
- Push the branch.
- Open a pull request.
- Use the repository PR template when available.

Never auto-merge a pull request.

## Source-of-truth before implementation

Before implementing a repo-specific issue, inspect the latest available repository state.

Preferred order:

- Use the GitHub connector for the latest committed `Koon-Kiat/SITBank` state when available.
- Use an uploaded repo zip, branch snapshot, or exact files for uncommitted local changes, private branch state, comparison work, or exact archived state.
- Ask for the latest repo snapshot or exact files when repository state is unavailable, stale, ambiguous, or insufficient.

Do not implement from memory, prior chat summaries, old zip files, or stale analysis.

## Branch rules

Create a new topic branch for implementation work.

Use a concise, descriptive branch name:

- Prefer `issue-number-short-summary` when an issue number exists, such as `123-fix-staging-readiness`.
- Otherwise use a short kebab-case name, such as `add-syft-sbom-workflow`.
- Do not use `main`, `master`, `production`, `staging`, or protected deployment branches for direct work.
- Do not force-push shared branches unless the user explicitly approves and the risk is explained.

If the intended branch already exists, either reuse it only when it clearly belongs to the same task or create a unique suffix.

## Implementation rules

Keep changes small and focused on the requested issue.

Before editing:

- Read the issue and related comments.
- Search for existing code, tests, docs, and workflows covering the touched boundary.
- Check for overlapping open PRs or issues when GitHub access is available.

During implementation:

- Follow `AGENTS.md` and the relevant `docs/codex/*.md` rules.
- Preserve existing security controls unless the issue explicitly requires a safe replacement.
- Add or update tests for changed behavior.
- Add or update documentation in the same change.
- Add or update stale-doc checks when a documented gap/status changes.
- Keep logs, audit metadata, workflow output, and generated artifacts sanitized.
- Do not commit secrets, environment files, private keys, provider exports, real customer data, real emails, or generated sensitive artifacts.

Do not broaden the task to unrelated refactors unless needed for safety or correctness.

## Commit rules

Before committing:

- Review the diff.
- Confirm only intended files are staged.
- Confirm no secrets or sensitive generated files are staged.
- Do not commit local virtual environments, caches, coverage output, generated SBOMs, logs, database dumps, or build artifacts unless the issue explicitly requires versioning them.

Use a clear sentence-style commit subject that independently explains the
change. The enforced subject policy is documented in
`docs/CONTRIBUTION_MESSAGE_POLICY.md`: start with a capital letter, use 12 to
72 characters, omit a trailing full stop, and avoid generic wording.

For a trivial, single-purpose change, a subject alone may be sufficient. For a
non-trivial, multi-issue, security-sensitive, deployment-sensitive, or
operational change, add a commit body. The body should explain:

- why the change is needed;
- the main behavior or trust boundaries affected;
- important security or compatibility decisions; and
- validation, deployment, migration, or provider impact when relevant.

Keep the subject concise and put detail in the body instead of compressing the
entire rationale into one line. For example:

```text
Harden private admin and origin controls

Use the protected environment as the private-host source of truth and update
the host verifier for the reviewed Tailscale status schema.

Require production origin-pull trust before Nginx reload while preserving the
raw-IP HTTP redirect and staging isolation.
```

Examples:

- `Add Syft SBOM workflow evidence`
- `Fix staging readiness behind Cloudflare origin protection`
- `Document HMAC helper false-positive handling`

Prefer one focused commit per issue unless multiple commits make review clearer.

## Push rules

Push only the implementation branch.

Do not push directly to protected branches.

Do not push credentials, generated secret material, raw provider output, or local-only files.

If push fails because of permissions, branch protection, authentication, or remote mismatch, stop and report the exact non-sensitive error.

## Pull request creation rules

When opening a PR:

- Read `.github/workflows/pr-title-policy.yml` and
  `docs/CONTRIBUTION_MESSAGE_POLICY.md` before choosing the title.
- Validate the title before creating the PR: it must start with a capital
  letter, contain 12 to 72 characters, have no leading/trailing whitespace,
  not end with a full stop, and not use generic or vague wording.
- Prefer a descriptive, unprefixed sentence-style title such as
  `Harden supply chain and private origin controls`.
- Do not add `[codex]`, `Codex:`, or another agent/tool attribution.
- Avoid category or Conventional Commit prefixes such as `Security:`, `Fix:`,
  `Feat:`, `Docs:`, and `Chore:` by default, even though the repository
  validator accepts capitalized forms. Use one only when the user explicitly
  requests it or the prefix materially improves classification.
- Use the repository PR template if `.github/pull_request_template.md`, `.github/PULL_REQUEST_TEMPLATE.md`, or `.github/PULL_REQUEST_TEMPLATE/*.md` exists.
- Preserve the template headings and fill them honestly.
- Link the related issue.
- Use `Closes #123` only when the PR fully resolves the issue.
- Use `Refs #123` or `Part of #123` when it is partial or preparatory.
- Keep the PR body concise and issue-specific.
- Mention tests run and documentation updated.
- Mention deployment, migration, secret, or provider impact only when relevant.
- Mention security-sensitive guardrails only when the PR touches that boundary.
- Do not paste raw secrets, provider exports, tokens, cookies, private keys, or sensitive logs.

If no PR template exists, use a compact fallback:

```markdown
## Summary

- TODO

## Tests

- TODO

## Documentation

- TODO

## Deployment impact

- TODO
```

Open a draft PR when:

- Implementation is incomplete.
- Required validation could not be run.
- A security or deployment decision needs reviewer input.
- The change depends on unavailable provider state or credentials.

## Validation reporting

Run relevant targeted tests when practical, then run:

```powershell
git diff --check
.\.venv\Scripts\python.exe -m pytest -q -n auto
```

If coverage-relevant source code, workflow tests, documentation checks, or test structure changed, generate coverage for SonarQube/SonarCloud import and ensure coverage remains at least 90% without weakening the quality gate.

Report validation honestly in the PR body and final response:

- List commands that passed.
- List commands that failed with non-sensitive error summaries.
- List commands not run and why.

Do not claim validation passed if it was not run.

## Review and merge rules

Do not approve, merge, auto-merge, close, or delete PRs unless the user explicitly asks for that action.

Do not bypass branch protection, required checks, CODEOWNERS review, GitHub Environment approvals, deployment gates, or quality gates.

If the PR changes high-risk security, authentication, authorization, cryptography, deployment, Cloudflare, Tailscale, Nginx, CI/CD, production guards, or database migrations, call out the review-sensitive areas clearly but concisely.
