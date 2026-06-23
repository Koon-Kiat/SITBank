# Contribution Message Policy

SITBank pull request titles and pull request commit subjects must use concise
sentence-style imperative wording.

## Required Format

Each PR title and commit subject must:

- Start with one approved capitalized imperative verb:
  `Add`, `Fix`, `Update`, `Remove`, `Refactor`, `Document`, `Improve`,
  `Secure`, `Configure`, `Align`, `Restore`, `Prevent`, `Validate`, `Enforce`,
  `Implement`, `Rename`, `Replace`, `Move`, `Create`, `Delete`, or `Test`
- Be at least 12 characters.
- Be at most 72 characters.
- Not end with a full stop.
- Not be a lazy or generic message such as `fix`, `update`, `changes`, `change`,
  `wip`, `test`, `misc`, `stuff`, `done`, `bug`, `final`, or `commit`.

Git-generated `Merge ...` and `Revert ...` commit subjects are allowed for the
commit-message check.

## Good Examples

- `Fix staging admin container startup`
- `Add dashboard security regression tests`
- `Remove inline styles blocked by CSP`
- `Update production deployment gating`

## Bad Examples

- `fix`
- `update`
- `WIP`
- `changes`
- `Fixed bug.`

## Why This Exists

Clear PR titles and commit subjects make audit trails easier to review, improve
release notes, and reduce ambiguity during incident response or rollback.
