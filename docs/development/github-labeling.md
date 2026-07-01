# GitHub Labeling

SITBank uses one tested policy in
`ops/security/github_label_policy.py` for new issues, pull requests, and
manual historical retagging. Auto-labels are triage aids, not authoritative
classifications; maintainers may correct them without changing application
behavior.

## Bounded automatic labels

The policy scores only high-confidence title terms, the focused `Summary`,
`Why`, `Required implementation`, `What changed`, and `Root cause` sections,
trusted base-branch changed paths, and branch names. Generic guardrails,
validation commands, test checklists, documentation inventories, and
deployment-impact boilerplate do not drive text labels.

At most six policy labels are automatically added to one item. New and edited
issues also receive `needs-triage`, which does not count toward that maximum.
Broad security or architecture changes may need more than six labels; a
maintainer adds those deliberately after review.

The principal taxonomy is:

- `security`: security behavior, secure configuration, auditability, or secure
  SDLC evidence.
- `auth`: login, registration, credential handling, identity proofing, or
  authentication policy.
- `session`: cookies, server sessions, CSRF-linked state, rotation, revocation,
  session HMAC, or session-bound decisions.
- `mfa`: TOTP, passkeys, WebAuthn, recovery codes, step-up, or MFA lifecycle.
- `admin`: admin application, routes, sessions, deployment boundary,
  root-admin bootstrap, or admin-only operations.
- `customer`: customer application, routes, accounts, or customer behavior.
- `database`: schema, migrations, database roles, permissions, audit tables,
  retention, or access patterns.
- `deployment`: deployment workflows, containers, EC2, Nginx, systemd,
  bootstrap, rollout, or release gates.
- `network-security`: Cloudflare, TLS/Nginx edge controls, origin protection,
  Tailscale, VPN/private access, headers, or network boundaries.
- `zero-trust`: Cloudflare Access, Tailscale, identity-aware access, or the
  private admin/staging access boundary.
- `staging`: the staging environment, hostname, deployment, or access controls.
- `frontend`, `dependencies`, `ci`, `documentation`, `tests`, `code-quality`,
  `python`, `audit`, and `banking`: only direct work in those areas.

`admin` and `customer` are both applied only when both domains are actually in
scope. Sensitive labels such as `mfa`, `session`, `database`, `deployment`,
`network-security`, `zero-trust`, and `staging` require focused terms or narrow
paths rather than incidental checklist words.

## Future issues and pull requests

`.github/workflows/issue-labeler.yml` runs for opened, reopened, and edited
issues. It checks out the policy from the trusted default branch, treats the
event title/body as data, and only adds labels.

`.github/workflows/pr-labeler.yml` runs for opened, synchronized, reopened, and
ready-for-review pull requests. It checks out only the trusted base commit,
loads changed path names through the GitHub API, and never checks out or
executes pull-request code. Normal PR labeling is additive, so Dependabot and
maintainer-applied labels remain in place. Neither workflow uses
`pull_request_target`.

`needs-triage` means a maintainer has not confirmed the issue classification.
Remove it after scope, ownership, priority, and labels have been reviewed.

## Manual historical retag

`.github/workflows/retag-labels.yml` is `workflow_dispatch` only. It can inspect
issues, pull requests, or both, and defaults to `dry_run: true`. Apply mode
requires the exact confirmation `RETAG`.

Dry run reports current, protected, removed, computed, and final expected
labels without mutation. Apply mode removes only unprotected item labels,
preserves protected labels, and adds the bounded shared-policy result. It never
deletes repository labels globally.

The protected automation-sensitive labels are:

- `dependencies`
- `docker`
- `github-actions`
- `python`

These identify Dependabot ecosystems and must survive manual retagging. Audit
new workflow, release, deployment, branch-protection, and Dependabot label
dependencies before changing this list.

To run a dry run, choose **Actions → Retag issue and pull request labels** and
keep `dry_run: true`. To mutate labels, review the dry-run output, set
`dry_run: false`, and set `confirm_retag: RETAG`.

## Manual correction

Maintainers may add or remove noisy labels directly after reviewing actual
scope. Keep automation-sensitive labels intact. If the same correction recurs,
add a representative test to `tests/test_github_issue_labeler.py` before
changing the shared rule; do not broaden common keywords merely to classify
one issue.
