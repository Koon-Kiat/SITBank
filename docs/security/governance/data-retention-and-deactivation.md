# Data Retention And Deactivation

This document records retention and deactivation expectations for SITBank.
It only claims deletion or anonymization behavior supported by code or runbooks.

Category: [Security governance](../README.md#governance).

## Deactivation, Deletion, And Anonymization

| Term | Meaning | Current support |
| --- | --- | --- |
| Deactivation | Prevent an account from authenticating or performing sensitive actions while retaining records | Supported through account status/freeze and staff/admin active-state checks |
| Deletion | Remove database rows and related records | Not exposed as a normal customer/admin self-service feature |
| Anonymization | Irreversibly remove or transform personal identifiers while retaining aggregate or audit-safe records | No automated workflow exists |

Use deactivation when the immediate goal is to stop access, contain a suspected
compromise, or offboard staff/admin accounts while preserving audit and banking
evidence. Do not delete or anonymize records during an incident without an
approved retention and evidence-preservation decision.

## Retention Expectations

| Record category | Retention expectation | Notes |
| --- | --- | --- |
| Customer account records | Retain while account exists and while needed for audit, security, and banking-like evidence | Deactivation should block use before any disposal decision |
| Staff/admin records | Retain while privileged access exists and while needed for invite, admin, and audit accountability | Disable/deactivate access when offboarding |
| Payee and transaction records | Retain while needed for customer banking history, dispute, audit, and integrity review | Do not remove related audit evidence silently |
| Security audit events | Retain for 7 years | `docs/OPERATIONS.md` states application code must not silently auto-delete audit rows |
| Alert reports and alert dedupe state | Preserve incident-relevant reports; dedupe state may be operational | Keep reports that support incident review outside transient delivery channels |
| Password reset tokens and transactions | Short-lived and one-time use | Expired transactions and unreferenced expired tokens are included in the approved security-state cleanup command |
| Manual recovery requests | Retain while active and while needed for review evidence | Public request does not unlock, freeze, or mutate an account by itself |
| Staff invite metadata | Retain while needed for invite lifecycle and staff onboarding accountability | Raw invite tokens must not be stored or logged |
| Registration OTP challenges | Short-lived, one-time use | Raw OTP is not stored; email hashes and OTP HMACs are security metadata |
| Server-side sessions and auth counters | Retain only for active/recent security enforcement | `app/security/state_cleanup.py` cleans selected expired security state |
| Encrypted backups | Retain according to operator backup policy | Backups contain personal, audit, and banking-like data; encrypted archives must stay root/operator-managed |

## Account Deactivation

Customer deactivation should:

- revoke or block active sessions where possible;
- preserve audit evidence;
- keep password reset/manual recovery separated from account unlock decisions;
- avoid deleting payee, transaction, and audit records without a reviewed
  retention decision.

Staff/admin deactivation should:

- disable privileged login or mark the staff/admin account inactive;
- revoke active admin sessions;
- revoke or rotate any deployment, Tailscale, Cloudflare, SSH, or SMTP secrets
  the user could access;
- preserve staff invite, admin action, and audit records.

Account freeze is a containment control, not deletion. Manual recovery can
force customer MFA re-enrollment and revoke sessions after root-admin review,
but public manual recovery submission does not change the account by itself.

## Retention-Aware Disposal

Before deleting or anonymizing data, verify:

1. The data is not required for audit-chain integrity, active incident review,
   dispute handling, legal/coursework evidence, or backup restoration.
2. Related records have a documented retention decision.
3. The operation will not break HMAC audit-chain verification.
4. A rollback or backup plan exists when appropriate.
5. The disposal summary records the approver, date range, record categories,
   and reason.

Security audit rows must not be silently auto-deleted by application code or
scheduled jobs. If disposal after retention is approved, keep a retained
summary of the deleted date range and approval.

## Approved Preserved-Category Procedures

The categories below are preserved by default and may be disposed of only by an
operator-approved maintenance record. The approval must name the category,
date range or record scope, reason, reviewer/approver, backup or rollback
decision, and retained summary. The retained summary must be aggregate or
opaque-reference only; do not copy personal data, raw alert bodies, manual
recovery evidence, invite tokens, decrypted backups, database URLs, secrets, or
raw audit payloads into issues, pull requests, screenshots, logs, or artifacts.

| Preserved category | Disposal or preservation decision | Required evidence |
| --- | --- | --- |
| Customer and staff/admin account records | Preserve while an account, dispute, incident, recovery case, staff lifecycle record, audit obligation, or coursework evidence requirement remains active. Prefer deactivation/freeze/offboarding over deletion. | Approval record, account-reference range, access-disabled evidence, affected-session revocation summary where applicable |
| Payees and transactions | Preserve for customer banking history, dispute handling, audit, integrity review, and restore validation. Disposal/anonymization requires a separate reviewed data minimization decision that proves related audit/dispute evidence remains coherent. | Date range, transaction/payee reference summary, dispute/incident hold check, backup/rollback decision |
| Manual recovery requests | Preserve pending, under-review, approved, denied, expired, cancelled, and completed request metadata needed to reconstruct root-admin review and maker-checker decisions. | Case-reference summary, final state, reviewer/approver record, notification/audit evidence without raw recovery material |
| Support ticket free-text context | Preserve customer-provided support-ticket free text while the related support need remains active. Staff queue summaries must stay minimized; detailed context is for the authorized detail/review workflow. | Case-reference summary, final state, reviewer record, minimized export evidence without raw secrets |
| Manual recovery request context | The anonymous request form stays low-friction: a later duplicate submission for the same active request replaces the stored optional reviewer-context reason (including clearing it to none when the later submission omits one), while request count, timestamps, and audit presence/length evidence are preserved regardless. Do not treat this as preserving every prior submission's context; only the latest submission's reason is retained on the active request. | Case-reference summary, final state, reviewer record, minimized export evidence without raw recovery material |
| Staff invite metadata | Preserve invite lifecycle metadata needed for privileged onboarding accountability; raw invite tokens remain non-stored/non-logged. Disposal requires proof the invite is terminal and no investigation hold applies. | Invite-reference summary, terminal state, workplace-domain evidence, approver record |
| Alert reports | Preserve incident-relevant alert reports and delivery summaries until the related investigation or review window closes. Dedupe state may expire through approved temporary security-state cleanup, but report evidence must not be silently deleted. | Alert count/severity summary, delivery outcome, investigation link or reviewer note, sanitized retained location |
| Security audit events | Preserve according to the 7-year audit-retention policy. Application code and timers must not delete audit-chain rows; any exceptional post-retention disposal requires a separate audit-chain integrity decision. | Audit date range, hash-chain verification outcome, approval record, retained aggregate summary |
| Investigation or held records | Preserve until the hold owner releases the hold. Disposal before release is prohibited. | Hold owner, release approval, scope summary |
| Encrypted backup archives | Preserve according to the operator backup policy, restore-drill needs, incident holds, and rollback requirements. Archive pruning is host/operator-owned and must never delete the only usable backup during an incident. | Archive basename-only summary, owner/mode evidence, restore-drill or replacement-backup evidence, approval record |

No weekly timer or application route performs destructive disposal for these
preserved categories. If future automation is proposed, it must start as a
dry-run report, require a category allowlist, keep destructive execution behind
explicit approval, fail closed on audit errors, and update this document and
tests before use.

## Approved Security-State Cleanup

`python -m flask --app wsgi:app security run-retention-cleanup` reviews
approved low-risk temporary security-state categories and defaults to dry-run.
It reports category-level counts for expired server-side sessions, auth
attempt counters, TOTP replay records, registration OTP challenges, password
reset transactions, unreferenced expired password reset tokens, security alert
dedupe rows, closed circuit-breaker state past retention, expired public
transaction idempotency rows, expired known-device rows, and terminal top-up
approval requests past retention. Mutating cleanup requires `--confirm`.

`cleanup-security-state` is a compatibility wrapper for this same workflow and
is also dry-run unless `--confirm` is supplied. Confirmed cleanup commits a
required `started` audit event before mutation. The mutations and required
`completed` event commit atomically; a missing start or completion event fails
closed, mutations roll back, and a separate `failed` event is attempted.

The command does not delete or anonymize customer accounts, staff/admin
accounts, payees, transactions, manual recovery requests or their reviewer
context, support tickets, staff invites, security audit events, investigation
or held records, alert reports, or encrypted backup archives. Treat those
categories as preserved until a reviewed retention decision and the
evidence-preserving procedure above are satisfied.

## Operator-Reviewed Retention Schedule

The `sitbank-retention-review@staging.timer` and
`sitbank-retention-review@production.timer` units generate a weekly,
aggregate-only dry-run report. The report must be reviewed by the application
owner and the destructive command must be separately approved and run with
`--confirm`; the timer never passes that flag. Broad unattended disposal,
including personal-data categories, manual recovery metadata, staff invites,
alert reports, and encrypted backups, remains prohibited by the approval
procedure above. No complete retention/disposal scheduler across those
preserved categories exists by design; any future scheduler must be reviewed as
a new change rather than inferred from the weekly report timer.

## Backup Retention

Encrypted backups are operational records containing personal data. Store only
`.pgdump.age` encrypted archives under the host backup directories, keep age
identity files outside the repository and application containers, and run the
restore preflight before any restore. Do not keep persistent plaintext `.dump`,
`.sql`, `.backup`, or `.pgdump` files.

Backup deletion must be operator-approved and should consider audit retention,
incident evidence, and restore requirements. Do not delete the only usable
backup during an incident.

Backup scheduling, restore drills, and encrypted-archive pruning are
host/operator-owned. Keep schedule evidence and restore-drill records outside
the repository, and never include decrypted content or age identity material.
