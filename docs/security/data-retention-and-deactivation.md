# Data Retention And Deactivation

This document records retention and deactivation expectations for SITBank.
It does not claim deletion or anonymization automation that is not implemented.

## Deactivation, Deletion, And Anonymization

| Term | Meaning | Current support |
| --- | --- | --- |
| Deactivation | Prevent an account from authenticating or performing sensitive actions while retaining records | Supported through account status/freeze and staff/admin active-state checks |
| Deletion | Remove database rows and related records | Not exposed as a normal customer/admin self-service feature |
| Anonymization | Irreversibly remove or transform personal identifiers while retaining aggregate or audit-safe records | Not implemented as an automated workflow |

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
| Password reset tokens and transactions | Short-lived and one-time use | Expiry exists; periodic disposal automation beyond state cleanup should be tracked before claiming it |
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

## Current Retention Automation Gap

The repository has expiry and cleanup for selected security state, but it does
not implement a complete retention/disposal scheduler for all personal-data
categories, manual recovery metadata, staff invites, password reset records,
alert reports, or encrypted backup archives. This remains tracked in
`docs/security/security-gap-register.md`.

## Backup Retention

Encrypted backups are operational records containing personal data. Store only
`.pgdump.age` encrypted archives under the host backup directories, keep age
identity files outside the repository and application containers, and run the
restore preflight before any restore. Do not keep persistent plaintext `.dump`,
`.sql`, `.backup`, or `.pgdump` files.

Backup deletion must be operator-approved and should consider audit retention,
incident evidence, and restore requirements. Do not delete the only usable
backup during an incident.
