# GitHub Labeling

This repository labels new issues and pull requests automatically, and provides
a manual workflow for safely retagging historical issues and PRs.

## Future Pull Requests

`.github/workflows/pr-labeler.yml` runs on `pull_request` for opened,
synchronized, reopened, and ready-for-review pull requests. It uses
the v6 `actions/labeler` action with `.github/labeler.yml` and
`sync-labels: false`. The workflow pins the action to an immutable commit SHA.

The PR workflow only adds computed labels. It does not remove existing labels,
so Dependabot labels and any maintainer-applied labels remain in place during
normal future PR labeling.

The PR workflow uses a trusted shell step for title, body, branch, file path,
and patch-text terms that `actions/labeler` does not cover directly. It does
not checkout or execute pull request code. The SHA-pinned `actions/labeler`
step still handles path-oriented labels from `.github/labeler.yml`.

The workflow must stay label-only. Do not add `actions/checkout`, do not
checkout PR branches, and do not execute scripts or code from pull requests in
that workflow. This repository intentionally avoids `pull_request_target`.

## Future Issues

`.github/workflows/issue-labeler.yml` runs when issues are opened, reopened, or
edited. It reads the issue title and body from the GitHub event payload and adds
matching labels. Every new or edited issue receives `needs-triage`.

The issue labeler only adds computed labels. It does not remove existing labels.
It applies `zero-trust`, `network-security`, and `staging` when titles or
bodies mention Cloudflare Access, Tailscale, VPN/private access, origin
bypass/protection, admin exposure, staging exposure, or staging deployment
terms.

## Manual Historical Retag

`.github/workflows/retag-labels.yml` is manual-only through
`workflow_dispatch`. It can retag issues, pull requests, or both, for open,
closed, or all items.

Retagging is intentionally more aggressive than future auto-labeling:

- It reads the current labels on each selected issue or PR.
- It preserves protected labels.
- It removes only unprotected labels from the individual issue or PR.
- It recomputes labels using the standard issue or PR label rules.
- It adds the recomputed labels.
- It never deletes repository labels globally.

The retag workflow defaults to dry-run mode. In dry-run mode it prints the
current labels, protected labels that would be preserved, unprotected labels
that would be removed, labels that would be added, and final expected labels.
It does not edit issues, PRs, or repository label metadata.

To dry-run a historical retag:

```text
Actions -> Retag issue and pull request labels -> Run workflow
target: both
state: all
limit: 500
dry_run: true
```

To apply a real retag:

```text
Actions -> Retag issue and pull request labels -> Run workflow
target: both
state: all
limit: 500
dry_run: false
confirm_retag: RETAG
```

If `dry_run` is `false` and `confirm_retag` is not exactly `RETAG`, the workflow
fails before changing labels.

## Protected Labels

Protected labels are preserved on each issue or PR during manual retagging.
They are not automatically added to every issue or PR.

The current protected labels come from `.github/dependabot.yml`:

- `dependencies`
- `docker`
- `github-actions`
- `python`

These labels must stay protected so Dependabot PRs do not lose labels that
identify their package ecosystem. The existing workflows were scanned before
adding the labeler workflows, and no additional issue/PR labels used by GitHub
Actions logic were found.

If a later workflow depends on a label in conditions, `gh issue edit
--add-label`, `gh issue edit --remove-label`, API calls, `labels:` blocks, or
other issue/PR label checks, add that label to `PROTECTED_LABELS` in
`.github/workflows/retag-labels.yml` before running a retag.

## Label Setup

The labeling workflows create or update the standard labels idempotently with
`gh label create --force`. This keeps label names, descriptions, and colors
available without deleting any repository labels.

Security/network labels added for zero-trust work:

- `zero-trust`: Identity-aware or private-network access boundary changes.
- `network-security`: Firewall, VPN, origin access, private access, or network
  boundary changes.
- `staging`: Staging environment, staging deployment, or staging access
  changes.

Code-quality work uses:

- `code-quality`: Static analysis, maintainability, coverage, or quality-gate
  work.
- `ci`, `security`, `documentation`, `tests`, and `python` remain additive
  when the changed paths or issue/PR text match those areas.

Issue, PR, and manual-retag text rules add `code-quality` for `SonarQube`,
`Sonar`, `quality gate`, `code quality`, `maintainability`, `coverage`,
`duplication`, and `technical debt`. Path rules cover the SonarQube workflow,
configuration, tests, and documentation. The existing `.github/workflows/**`
rule also adds `ci`.

Path rules:

- `ops/nginx/**` receives `deployment`, `network-security`, and `security`.
- `ops/deploy/**` receives `deployment`.
- `compose.staging.yml`, staging env templates, and staging deployment files
  receive `staging` and `deployment`.
- `docs/security/**` receives `documentation` and `security`.
- Admin deployment, admin Nginx, and admin isolation docs/tests receive
  `admin` and `security`.
- Zero-trust, Cloudflare, Tailscale, and private-access docs receive
  `zero-trust`, `network-security`, `documentation`, and `security`.
- `.github/workflows/sonarqube.yml`, `sonar-project.properties`, the SonarQube
  policy test, and its documentation receive `code-quality`; Python files and
  Python dependency manifests receive `python`.
