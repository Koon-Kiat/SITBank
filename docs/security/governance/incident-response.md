# Incident Response

This runbook covers suspected SITBank security and privacy incidents. It
complements `SECURITY.md`, `docs/OPERATIONS.md`, and
`docs/security/assurance/audit-and-alerting.md`. Role-based escalation and post-incident
documentation review expectations are defined in
`docs/security/governance/security-governance.md`.

Category: [Security governance](../README.md#governance).

## First Response

1. Preserve evidence before making broad changes.
2. Keep secrets and personal data out of public issues, chat, screenshots, and
   incident notes.
3. Record UTC time, environment, commit SHA, image digest, affected account or
   public references, and who took each action.
4. Use sanitized audit references instead of raw identifiers when possible.
5. Choose containment that stops harm while preserving audit integrity.

Never share passwords, TOTP codes, recovery codes, reset links, raw session IDs,
cookies, CSRF tokens, API tokens, webhook URLs, private keys, database URLs with
credentials, decrypted backups, or full request bodies containing secrets.

## Suspected Data Breach

Preserve:

- `security_audit_events` rows and exported audit anchors;
- alert JSON reports and delivery failure summaries;
- Nginx, Docker, journald, deployment, and database logs;
- relevant GitHub Actions run IDs, signed image digests, and deployed revision;
- backup metadata without exposing decrypted dump contents.

Contain:

- freeze or deactivate affected customer accounts when account misuse is likely;
- deactivate staff/admin accounts if privileged misuse is suspected;
- revoke sessions and rotate affected secrets;
- disable unsafe public access paths rather than weakening authentication or
  audit controls.

Escalate privately to the Security Owner and Deployment Owner. Public
issues must not include personal data, exploit details, credentials, session
identifiers, or production logs.

## Suspicious Admin Action

1. Preserve admin audit events, staff invite events, manual recovery events,
   Tailscale/Cloudflare access logs, and Nginx logs.
2. Revoke the staff/admin account's active sessions.
3. Disable or deactivate the staff/admin account if misuse is plausible.
4. Rotate deployment, SSH, Tailscale, Cloudflare, SMTP, or database secrets the
   account could access.
5. Review related manual recovery and staff invite changes.

Do not expose the admin app publicly as a shortcut during recovery. Keep the
Tailscale/private-access boundary and Flask admin TOTP requirements in place.

## Audit Chain Degradation

Treat audit-chain failure, anchor mismatch, table rewind, tail deletion, or
append-only privilege failure as evidence-preservation events.

```bash
python -m flask --app wsgi:app verify-audit-log-chain
python -m flask --app wsgi:app verify-audit-log-chain --anchor /var/lib/sitbank/security-audit.anchor
python -m flask --app wsgi:app check-security-alerts --report-only
```

Stop routine anchor rotation until investigation completes. Preserve the
mismatched anchor, current database state, deployment revision, and host logs.
Do not run manual SQL updates or deletes against `security_audit_events` to
"fix" the chain.

## Alert Delivery Failure

1. Run `check-security-alerts --report-only --no-delivery` to preserve a local
   sanitized report.
2. Verify `SECURITY_ALERT_WEBHOOK_URL_FILE`, timeout, min severity, and dedupe
   settings without printing the webhook URL.
3. Rotate the webhook URL if it may have been exposed.
4. Keep alert delivery failures in the incident record by error type only.

Security alert channels must never deliver password reset links, recovery
codes, MFA secrets, private keys, raw request bodies, database dumps, or full
account numbers.

## Leaked Secret

1. Revoke the exposed credential at its source.
2. Install a replacement through the root-managed secret file path.
3. Restart or redeploy only the affected service through the normal reviewed
   workflow.
4. Run `production-check` and relevant smoke checks.
5. Revoke sessions when session, Flask, CSRF, MFA KEK, or database credentials
   are rotated.
6. If committed, coordinate history cleanup and treat the original secret as
   compromised even after removal.

## Compromised Customer Account

- Freeze or deactivate the account when ongoing misuse is likely.
- Revoke active sessions.
- Use password reset or manual recovery only through the supported flows.
- Require MFA re-enrollment after approved manual recovery completion where
  appropriate.
- Preserve account, session, payee, reset, manual recovery, and audit events.

## Compromised Staff/Admin Account

- Disable or deactivate the staff/admin account.
- Revoke admin sessions.
- Rotate any host/cloud/deployment secrets the account could access.
- Review staff invite, manual recovery, and admin configuration events.
- Remove Cloudflare/Tailscale access and device approvals as needed.

## Backup Exposure

Encrypted `.pgdump.age` backup exposure requires recipient and access review.
Decrypted dump, plaintext `.dump`, `.sql`, `.backup`, `.pgdump`, age identity,
or database credential exposure requires immediate rotation and containment.

Preserve file paths, timestamps, ownership/mode output, and access logs. Do not
paste dump contents into incident notes.

## Account Deactivation During Incidents

Use deactivation or freeze when continued access could increase harm. Do not
delete or anonymize accounts during active investigation unless a separate
approved retention decision exists. Deactivation preserves audit, banking-like,
and security evidence while blocking access.

## Post-Incident Review

After containment and recovery:

- record root cause, affected data categories, timeline, controls that worked,
  and controls that need improvement;
- update the gap register, framework matrix, runbooks, and tests;
- rotate any temporary credentials used during response;
- retain sanitized evidence according to `docs/security/governance/data-retention-and-deactivation.md`.
