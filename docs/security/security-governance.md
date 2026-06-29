# Security Governance

This document is the source of truth for SITBank security ownership, review
cadence, risk tracking, accepted-risk handling, and documentation upkeep. It is
a lightweight project process, not a certification, audit approval, or legal
compliance statement.

Related evidence:

- `docs/security/security-gap-register.md`
- `docs/security/design-risk-register.md`
- `docs/security/framework-control-matrix.md`
- `docs/security/threat-model.md`
- `docs/CONTRIBUTION_MESSAGE_POLICY.md`

## Roles

Use role names in repository documents unless a real assignment already exists
outside the repo.

| Role | Owns | Typical evidence |
| --- | --- | --- |
| Security Owner | Security review, gap triage, accepted-risk decisions, urgent escalation | Gap register, incident notes, security test results |
| Backup Reviewer | Second review for auth, session, admin, deployment, audit, and accepted-risk changes | Pull request review, test evidence |
| Application Owner | Application code, tests, migrations, auth/session/admin behavior, runtime guardrails | Tests, migrations, service docs |
| Deployment Owner | CI/CD, EC2, Nginx, Docker, TLS, release evidence, deployment gates | Workflow runs, deployment logs, host checks |
| Documentation Owner | Framework matrix, gap register, threat model, runbooks, stale-documentation cleanup | Documentation diffs and doc tests |
| Risk Owner | Role accountable for a specific gap, design risk, or accepted risk | Register owner/status/review fields |
| Reviewer | Person or role checking that evidence matches the claim before merge | PR review and validation commands |
| External operator / outside repo | Cloud, IdP, DNS, tailnet, certificate, or host process not fully controlled in git | Operator notes, live verification output |

When no person is assigned, use the responsible role plus `needs-triage` instead
of inventing a named owner.

## Review Cadence

Run a lightweight security review:

- before production deployment or major staging promotion;
- at least once per milestone or release cycle;
- after auth, session, admin, deployment, audit, alerting, backup, privacy, or
  zero-trust boundary changes;
- after high or critical dependency, scanner, or secret-scanning findings;
- after an incident, high-severity alert, or accepted-risk review trigger;
- before closing a security gap that changes the implemented control state.

Monthly review is useful when the project is active, but the minimum commitment
for this student repository is once per milestone or release cycle.

## Review Checklist

Use this short checklist during security reviews:

- open security gaps and `needs-triage` entries have an owner role;
- current open gaps have status, tracking, and next review trigger;
- accepted risks still have a reason, compensating controls, and trigger;
- design-risk rows still match code, docs, workflows, and operator evidence;
- dependency, SAST, DAST, secret-scanner, and Trivy findings are reviewed;
- deployment gates, production guard, and smoke/DAST evidence remain current;
- admin/staging private-access and off-repo prerequisites have current evidence;
- closed security gaps updated the gap register, framework matrix, threat
  model, design risk register, and runbooks where relevant;
- documentation tests cover new governance, risk, or framework claims.

## Tracking Format

Open gaps and design risks should record these fields where practical:

- owner role, for example `Owner: Security Owner`;
- status, for example `Open gap`, `Implemented`, `Partially implemented`,
  `Accepted risk`, `External prerequisite`, `Deferred`, or `needs-triage`;
- accepted-risk marker and reason when work is intentionally deferred;
- compensating controls for accepted or partially implemented risks;
- target review cadence or next review trigger;
- external owner/process when the control is outside the repository;
- evidence source such as tests, workflows, docs, or operator output.

Each important open security gap must have an explicit status, owner role,
next action, and review trigger. Accepted risks, external prerequisites,
deferred items, and out-of-scope items must state why they are not currently
implemented.

## Accepted Risks

Accepted risks are visible project decisions, not a way to hide work. Record:

- owner role;
- reason for acceptance;
- compensating controls;
- documentation or evidence reference;
- review cadence or next review trigger;
- condition that reopens the risk.

Temporary acceptance should include a review trigger such as the next milestone,
production deployment, provider change, or relevant architecture change.

## Off-Repo Ownership

Some controls depend on systems outside this repository, such as Cloudflare
Access tenant settings, Tailscale ACL and device approval, AWS IAM/OIDC/SSM,
EC2 security groups, DNS, certificates, and any future SonarQube project
administration. For those risks, record:

- `Owner: External operator / outside repo` or the closest role;
- what external system or operator process owns the action;
- what evidence should be reviewed;
- where the repo records current status;
- what is blocked until the external action is complete;
- the next review trigger.

Repository documentation alone does not make an off-repo control implemented.
Mark it as partially implemented, external prerequisite, accepted risk, or open
gap until live evidence supports the stronger claim.

## Stale Documentation Prevention

Every security change or gap closure should check whether these docs need updates:

- `docs/security/security-gap-register.md`
- `docs/security/framework-control-matrix.md`
- `docs/security/design-risk-register.md`
- `docs/security/threat-model.md`
- `docs/OPERATIONS.md`
- `docs/DEPLOYMENT.md`
- `SECURITY.md`

When a gap closes, move it out of current open gaps, add implemented or partial
evidence, update framework mappings, and add or update doc tests. When a control
is only partially implemented, leave the remaining work visible with an owner
role, status, and review trigger.

## Urgent Escalation

For suspected active compromise, exposed secrets, admin misuse, audit-chain
failure, public admin exposure, or high-severity scanner findings:

1. Keep secrets and personal data out of public records and chat.
2. Preserve timestamps, commit SHA, image digest, workflow run IDs, and sanitized
   audit references.
3. Escalate privately to the Security Owner and Deployment Owner.
4. Use `docs/security/incident-response.md` for containment and recovery.
5. Record follow-up actions or accepted-risk decisions after containment.

## Limitations

This process is intentionally small. It does not prove live cloud, DNS,
certificate, tailnet, IdP, EC2, or production state by itself. It also does not
create a formal security team. The repository records role-based accountability
and evidence expectations; operators still need to retain live verification
outside the repo when controls depend on external systems.
