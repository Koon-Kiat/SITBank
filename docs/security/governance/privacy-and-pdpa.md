# Privacy And PDPA

This document records SITBank's Singapore PDPA-focused personal-data handling
expectations. SITBank is a coursework banking simulation, but operators should
treat submitted identity, account, audit, security, and banking-like records as
protected personal data.

Category: [Security governance](../README.md#governance).

## Data Inventory

| Data category | Purpose | Minimization and handling |
| --- | --- | --- |
| Customer name | Account display, support, audit context | Required at registration; do not copy into alert payloads unless needed for a reviewed support workflow |
| Customer email | Customer email verification, login identifier, reset/recovery email | Staff/admin workplace domains are blocked for customer registration; audit metadata uses references where possible |
| Customer phone | Registration contact metadata, customer profile correction, and PayUp lookup | Exactly eight ASCII digits starting with `8` or `9`; Unicode digit lookalikes, separators, whitespace, and country-code variants are rejected; optional for preserved legacy rows; profile changes require TOTP; do not use as an authenticator or log raw phone values |
| PayUp display nickname | Customer-owned PayUp party display | Optional until first PayUp send, then required; 2 to 128 characters; separate from `Payee.nickname`; audit metadata stores nickname presence and length, not raw nicknames |
| Account identifiers | Customer account routing, payee setup, display | Generated server-side; UI masks account numbers where possible; audit events use references |
| Payee records | Customer-managed payment recipients | Scoped to owner; recipient lookup occurs only after TOTP step-up; audit events use account references and nickname presence/length metadata instead of raw account numbers or customer-entered nicknames |
| Transaction records | Banking-like workflow evidence and validation | Keep business records only for implemented flows; avoid storing client-controlled server fields |
| Staff/admin identity | Admin login, authorization, accountability | Invite-only staff/admin accounts with role checks and mandatory TOTP |
| Staff/admin workplace email | Workplace verification, admin login, and staff invite delivery | Must satisfy approved workplace domain policy; do not use personal email for privileged login or invite contact |
| Staff invite metadata | Staff onboarding and invite audit trail | Store normalized workplace email metadata and token HMACs; raw invite tokens and personal backup email contacts must not be logged |
| Audit event metadata | Security accountability and incident review | Redact sensitive keys and values recursively; use HMAC-derived references for raw identifiers |
| Alert metadata | Operator notification and security monitoring | Sanitize before delivery; webhook URLs and tokens are secrets |
| Session/security metadata | Session integrity, rate limiting, OTP/reset state, alert dedupe | Stored in application-owned PostgreSQL tables; browser cookies carry opaque identifiers only |
| Backup data | Recovery from database loss or migration failure | Encrypted with host-managed age recipients; plaintext dumps exist only in root-only temporary directories |

Protected health or medical data is Not applicable to the current codebase.
Health/medical data must not be added without a separate privacy and security
review.

## Access Expectations

Customer data is available only through authenticated customer routes scoped to
the current user, or through explicit admin/operator workflows that have a
documented purpose. Staff/admin access is separated into the admin runtime with
separate cookies, session keys, database role, invite lifecycle, and mandatory
TOTP.

Database access is split between migration/owner and runtime roles. The Flask
runtime role must not own schema objects or have DDL privileges. Audit rows are
append-only to the runtime role after migrations.

Operators should use least privilege:

- customer support actions must use the minimum record needed;
- staff/admin accounts must be removed or disabled when no longer needed;
- deployment and backup keys must be scoped to their operational purpose;
- private access systems such as Cloudflare Access and Tailscale remain
  operator-managed and are not committed.

## Logging And Redaction

Do not log, paste, or send through alert channels:

- passwords, password confirmations, or password reset URLs;
- TOTP codes, recovery codes, OTP codes, MFA secrets, nonces, ciphertext, KEK
  material, or HMAC keys;
- raw session IDs, cookies, CSRF tokens, signed session payloads, or database
  URLs with credentials;
- private SSH keys, age identities, AWS credentials, Cloudflare or Tailscale
  tokens, webhook URLs, or SMTP passwords;
- full request bodies containing secrets;
- real database dumps or decrypted backups.

`app/security/audit.py` sanitizes audit metadata before persistence and
structured log output. `app/security/alerts.py` performs a final sanitization
pass before webhook delivery. Use `audit_reference()` and
`principal_reference()` for stable HMAC-derived references instead of raw
identifiers.

## Third-Party Services

| Service | Data involved | Handling expectation |
| --- | --- | --- |
| SMTP provider | Registration OTP, reset, invite, and recovery notification email content | Use TLS and root-managed SMTP credentials in production |
| Discord or HTTPS alert webhook | Sanitized alert summaries only | Webhook URL is secret; never send reset links, recovery codes, raw identifiers, or dumps |
| Have I Been Pwned range API | First five SHA-1 hex characters of a candidate password hash | Use Add-Padding and timeouts; SHA-1 is not used for password storage |
| Cloudflare Access / Authenticated Origin Pull | Staging access decision and origin-pull client certificate state | Tokens and certificates are operator-managed and not committed |
| Tailscale | Private admin/operator network access | Tailnet policy, auth keys, and device state are operator-managed |
| GitHub Actions / GHCR | Build/deploy metadata, signed image digests | Do not store long-lived application secrets in workflow files |
| AWS/EC2 | Host, security group, instance profile, logs where configured | IAM, SSM, and security-group changes require AWS administrator control |

## Access And Correction

Customers can update allowed account details through authenticated, CSRF
protected routes that require TOTP step-up for sensitive profile changes.
Administrative correction outside self-service must be handled through a
documented support/admin workflow and must preserve audit evidence.

Account deletion or anonymization is not a normal self-service feature in the
current codebase. Use the deactivation and retention guidance in
`docs/security/governance/data-retention-and-deactivation.md`.

## Breach Escalation

Suspected personal-data exposure must follow
`docs/security/governance/incident-response.md`. Preserve audit logs, alert reports,
deployment evidence, relevant backups, and host logs. Do not put secrets,
personal-data dumps, reset links, recovery codes, or full request bodies into
public issues, chat, screenshots, or incident notes.
