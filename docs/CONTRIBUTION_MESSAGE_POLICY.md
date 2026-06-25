# Contribution Message Policy

SITBank pull request titles and pull request commit subjects must use concise,
capitalized wording. Sentence-style titles and capitalized Conventional Commit
style are both allowed.

## Required Format

Each PR title and commit subject must:

- Start with a capital letter.
- Be at least 12 characters.
- Be at most 72 characters.
- Not end with a full stop.
- Not have leading or trailing whitespace.
- Not be a lazy or generic message such as `fix`, `update`, `updates`,
  `changes`, `change`, `wip`, `test`, `tests`, `misc`, `stuff`, `done`, `bug`,
  `bugs`, `final`, `commit`, `temp`, `tmp`, `work`, or `progress`.
- Not use vague phrases such as `fix bug`, `fix issue`, `update stuff`,
  `make changes`, or `minor changes`.

Git-generated `Merge ...` and `Revert ...` commit subjects are allowed for the
commit-message check.

Capitalized Conventional Commit prefixes are allowed, including scopes:

- `Fix: staging admin secret wiring`
- `Feat: add admin deployment boundary`
- `Chore(deps): bump msgpack to 1.2.1`

Lowercase Conventional Commit prefixes are rejected:

- `fix: staging admin secret wiring`
- `feat: add admin deployment boundary`
- `chore(deps): bump msgpack to 1.2.1`

## Good Examples

- `Fix staging admin container startup`
- `Add dashboard security regression tests`
- `Remove inline styles blocked by CSP`
- `Update production deployment gating`
- `Security: harden admin session validation`
- `Production deployment is manual only`

## Bad Examples

- `fix`
- `update`
- `WIP`
- `changes`
- `Fixed bug.`
- `update stuff`
- `minor changes`

## Why This Exists

Clear PR titles and commit subjects make audit trails easier to review, improve
release notes, and reduce ambiguity during incident response or rollback.

## PR Description Requirements

Pull requests must also fill in the repository PR template. The description
must include these sections, either as plain headings or Markdown headings:

- `Summary`
- `Why`
- `What changed`
- `Security impact`
- `Deployment impact`
- `Verification`
- `Notes`

Every section except `Notes` must contain meaningful content. `Notes` may use
`None`, `N/A`, or `No follow-up required` when there is nothing to add.

Do not leave template placeholder text in the PR description. A custom paragraph
above an unchanged template still fails validation.

`Deployment impact` must state at least one concrete impact, such as
`staging deployment`, `production deployment`, `database migration`,
`secret changes`, or `No deployment action required`.

`Verification` must include at least one test command, manual verification step,
CI check, or a short explanation of why verification was not run.
