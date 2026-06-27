# Framework Control Matrix

This matrix maps SITBank's current repository evidence to common security
frameworks. It is not a certification claim; it is an evidence index for code,
tests, deployment controls, and follow-up work. Current open items are tracked
only in `docs/security/security-gap-register.md`.

External framework references:

- OWASP ASVS 5.0.0: <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP Top 10 2025: <https://owasp.org/www-project-top-ten/>
- NIST SP 800-218 SSDF: <https://csrc.nist.gov/pubs/sp/800/218/final>
- OWASP SAMM: <https://owaspsamm.org/model/>
- Singapore PDPA: <https://www.pdpc.gov.sg/about/the-legislation/pdpa-overview>
- OWASP API Security Top 10 2023: <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- CIS Controls v8: <https://www.cisecurity.org/controls/v8>
- NIST SP 800-63B: <https://pages.nist.gov/800-63-4/sp800-63b.html>
- MAS Technology Risk Management / Cyber Hygiene: <https://www.mas.gov.sg/>
- CWE Top 25: <https://cwe.mitre.org/top25/>

## Status Legend

| Status | Meaning |
| --- | --- |
| Implemented | Code, tests, or committed operational scripts support the control |
| Partially implemented | Repository controls exist, but live infrastructure, UI, policy, or documentation work remains |
| Not applicable | The framework area does not apply to this project or current architecture |
| Open gap | The control is missing or intentionally deferred |
| Needs verification | The control depends on live host/cloud state outside this repository |

## OWASP ASVS 5.0.0

| Control area | Status | Relevant files | Relevant tests | Current evidence | Remaining gaps / follow-up |
| --- | --- | --- | --- | --- | --- |
| Authentication and MFA | Implemented | `app/auth/services.py`, `app/admin/services.py`, `app/security/passwords.py` | `tests/test_auth_registration_login.py`, `tests/test_mfa_lifecycle.py`, `tests/test_passwords.py` | Generic login errors, dummy hash, PBKDF2+pepper, TOTP, recovery codes, fresh step-up for recovery-code regeneration | Full previous-password history is open |
| Session management | Partially implemented | `app/security/sessions.py`, `config.py` | `tests/test_session_management.py`, `tests/test_session_absolute_lifetime.py`, `tests/test_db_session_integrity.py` | PostgreSQL-backed opaque sessions, HMAC-wrapped payloads, idle expiry, absolute lifetime, revocation, inventory | Optional active-session cap and device-bound proof are open |
| Access control | Implemented | `app/web/routes.py`, `app/banking/routes.py`, `app/admin/routes.py` | `tests/test_route_inventory_security.py`, `tests/test_admin_route_inventory_security.py`, `tests/test_payee_management_security.py` | Customer/admin route inventories, admin isolation, direct banking MFA gate, payee ownership tests | None currently tracked for core route authorization |
| Input validation and output encoding | Implemented | `app/auth/forms.py`, `app/banking/forms.py`, `app/auth/schemas.py`, templates | `tests/test_banking_transaction_security.py`, `tests/test_authenticated_portal_ui.py`, `tests/test_owasp_regressions.py` | WTForms/Marshmallow/service validation, template autoescape, no user-controlled `|safe` | Continue adding tests for new input surfaces |
| Cryptography and secrets | Implemented | `app/security/crypto.py`, `app/security/session_hmac.py`, `ops/nginx/sitbank-tls-policy.conf` | `tests/test_mfa_envelope_crypto.py`, `tests/test_config.py`, `tests/test_deployment.py` | MFA envelope encryption, session/audit HMAC, host TLS policy, root-managed secret files | Live TLS evidence remains deployment-state verification |
| Logging and monitoring | Partially implemented | `app/security/audit.py`, `app/security/alerts.py`, `app/ops/commands.py` | `tests/test_audit_alerting.py`, `tests/test_audit_metadata_sanitization.py` | Sanitized audit rows, HMAC hash chain, alert dedupe and delivery sanitization | Admin audit-log viewer UI is open; CLI/report review exists |

## OWASP Top 10 2025

| Control area | Status | Relevant files | Relevant tests | Current evidence | Remaining gaps / follow-up |
| --- | --- | --- | --- | --- | --- |
| Broken access control | Implemented | `app/banking/routes.py`, `app/admin/routes.py`, `app/admin/separation.py` | `tests/test_payee_management_security.py`, `tests/test_admin_route_inventory_security.py`, `tests/test_admin_isolation.py` | Ownership filters, route inventories, admin/customer isolation, staff self-action guard | None currently tracked for implemented route surfaces |
| Cryptographic failures | Partially implemented | `ops/nginx/sitbank-tls-policy.conf`, `app/security/crypto.py`, `ops/backups/*` | `tests/test_mfa_envelope_crypto.py`, `tests/test_backup_security.py`, `tests/test_deployment.py` | TLS policy, AES-GCM MFA envelopes, PBKDF2+pepper, encrypted backups | Live TLS/certificate posture needs host evidence |
| Injection and SSRF | Implemented | `app/banking/services.py`, `app/auth/routes.py`, `app/security/passwords.py` | `tests/test_banking_transaction_security.py`, `tests/test_owasp_regressions.py` | SQLAlchemy query construction, payload allowlists, open-redirect regression tests, fixed HIBP endpoint | Add allowlist tests for any future outbound integrations |
| Security misconfiguration | Partially implemented | `config.py`, `app/security/production_guard.py`, `ops/ssh/99-sitbank-hardening.conf` | `tests/test_production_guard.py`, `tests/test_ec2_ssh_hardening_docs.py`, `tests/test_deployment.py` | Production fail-closed guard, Docker hardening, OpenSSH drop-in template | EC2 SSH/UFW/security-group rollout is an operator action |
| Vulnerable and outdated components | Partially implemented | `.github/workflows/ci-deploy.yml`, `scripts/ci-local`, lockfiles | `tests/test_deployment.py`, `tests/test_secret_scanner.py` | Hash-locked Python deps, dependency review, pip-audit, Trivy, CodeQL, Bandit | Ordinary-PR authenticated DAST remains a policy tradeoff |
| Identification and authentication failures | Partially implemented | `app/auth/services.py`, `app/auth/password_reset.py` | `tests/test_password_reset.py`, `tests/test_account_security_actions.py` | Reset token exchange, MFA onboarding, session revocation, generic errors | Full previous-password history is open |
| Logging and monitoring failures | Partially implemented | `docs/security/audit-and-alerting.md`, `docs/security/incident-response.md`, `app/security/alerts.py` | `tests/test_audit_alerting.py`, `tests/test_privacy_pdpa_docs.py` | Audit hash chain, alert scheduler, sanitized delivery, incident workflows | Admin audit viewer UI remains open |

## NIST SP 800-218 SSDF

| Control area | Status | Relevant files | Relevant tests | Current evidence | Remaining gaps / follow-up |
| --- | --- | --- | --- | --- | --- |
| Prepare the organization | Partially implemented | `docs/security/security-gap-register.md`, `docs/security/framework-control-matrix.md` | `tests/test_framework_control_docs.py` | Framework matrix and centralized gap register exist | Formal ownership and recurring review cadence are documentation follow-up |
| Protect the software | Implemented | `.github/workflows/ci-deploy.yml`, `ops/deploy/*`, `Dockerfile` | `tests/test_deployment.py` | Pinned actions/images, signed digests, protected main deployment, restricted wrappers | OIDC + SSM migration remains optional follow-up |
| Produce well-secured software | Implemented | `app/`, `config.py`, `ops/security/*` | Full pytest, CodeQL, Bandit, dependency tests | Secure coding controls, route inventories, production guard, secret scanner | Continue adding tests for new features |
| Respond to vulnerabilities | Implemented | `SECURITY.md`, `docs/OPERATIONS.md`, `docs/security/incident-response.md`, `.github/dependabot.yml` | `tests/test_privacy_pdpa_docs.py`, `tests/test_deployment.py` | Dependabot review-only policy, vulnerability exception policy, monitoring commands, and incident workflows are documented | Keep incident playbooks updated after exercises |

## OWASP SAMM

| Control area | Status | Relevant files | Relevant tests | Current evidence | Remaining gaps / follow-up |
| --- | --- | --- | --- | --- | --- |
| Governance | Partially implemented | `docs/security/security-gap-register.md`, `docs/CONTRIBUTION_MESSAGE_POLICY.md` | `tests/test_framework_control_docs.py`, `tests/test_deployment.py` | Gap register, commit/PR policy, release gates | Assign recurring risk owners outside the repo |
| Design | Implemented | `docs/security/threat-model.md`, `docs/security/design-risk-register.md`, `docs/security/access-control.md`, `docs/security/cryptography-and-authentication.md` | `tests/test_threat_model_docs.py`, `tests/test_route_inventory_security.py`, `tests/test_admin_route_inventory_security.py` | Threat model, design risk register, access-control docs, and crypto architecture docs | Keep model/register updated when architecture changes |
| Implementation | Implemented | `app/`, `ops/security/*`, lockfiles | `tests/test_owasp_regressions.py`, `tests/test_deployment.py` | Input validation, output encoding, SAST, dependency locks, secret scanner | Continue feature-specific tests |
| Verification | Partially implemented | `tests/`, `.github/workflows/ci-deploy.yml`, `scripts/ci-local` | `tests/test_deployment.py` | Full pytest, DAST on release/schedule, smoke tests | Authenticated DAST on ordinary PRs remains a policy tradeoff |
| Operations | Partially implemented | `docs/OPERATIONS.md`, `docs/security/ec2-ssh-and-deployment-access.md` | `tests/test_ec2_ssh_hardening_docs.py`, `tests/test_deployment.py` | Alert timer, backup tooling, SSH hardening runbook | Live EC2 SSH/UFW and zero-trust state need operator validation |

## Singapore PDPA

| Control area | Status | Relevant files | Relevant tests | Current evidence | Remaining gaps / follow-up |
| --- | --- | --- | --- | --- | --- |
| Protection obligation | Implemented | `docs/security/privacy-and-pdpa.md`, `app/security/audit.py`, `config.py`, `ops/backups/*` | `tests/test_privacy_pdpa_docs.py`, `tests/test_audit_metadata_sanitization.py`, `tests/test_backup_security.py` | Personal-data categories, minimization, redaction, encrypted backups, root-managed secret files, and TLS policy are documented/tested | Live host controls need operator evidence |
| Retention limitation | Partially implemented | `docs/security/data-retention-and-deactivation.md`, `docs/OPERATIONS.md`, `app/security/state_cleanup.py` | `tests/test_privacy_pdpa_docs.py`, `tests/test_deployment.py` | Audit retention, deactivation/deletion/anonymization distinction, and selected security-state cleanup are documented | Complete retention/disposal scheduler remains open |
| Access/correction and accountability | Implemented | `docs/security/privacy-and-pdpa.md`, `app/auth/services.py`, `docs/security/audit-and-alerting.md` | `tests/test_privacy_pdpa_docs.py`, `tests/test_account_security_actions.py`, `tests/test_audit_alerting.py` | Account update expectations, audit trail, and breach escalation path are documented | Continue documenting new data categories as features are added |

## OWASP API Security Top 10

| Control area | Status | Relevant files | Relevant tests | Current evidence | Remaining gaps / follow-up |
| --- | --- | --- | --- | --- | --- |
| Object and function authorization | Implemented | `app/banking/routes.py`, `app/auth/routes.py`, `app/admin/routes.py` | `tests/test_payee_management_security.py`, `tests/test_route_inventory_security.py`, `tests/test_admin_route_inventory_security.py` | BOLA/BFLA controls through ownership filters, route inventories, CSRF and MFA gates | None currently tracked for implemented API routes |
| Authentication | Implemented | `app/auth/services.py`, `app/security/sessions.py` | `tests/test_auth_registration_login.py`, `tests/test_session_management.py` | Generic auth, TOTP, recovery codes, server-side sessions | Password history remains open |
| Object property authorization and mass assignment | Implemented | `app/auth/forms.py`, `app/admin/services.py`, `app/banking/schemas.py` | `tests/test_owasp_regressions.py`, `tests/test_admin_staff_invites.py` | Forged privileged fields rejected; URL-like mass assignment blocked | Continue coverage for new APIs |
| Resource consumption and business flows | Partially implemented | `app/security/rate_limits.py`, route decorators, `.github/workflows/ci-deploy.yml` | `tests/test_route_inventory_security.py`, `tests/test_audit_alerting.py` | Rate-limit inventory and alerting exist | Authenticated DAST PR coverage remains a tradeoff |
| Security misconfiguration and inventory | Partially implemented | `tests/test_route_inventory_security.py`, `tests/test_admin_route_inventory_security.py` | Same | Generated route inventories exist | Live EC2 firewall and security-group posture need operator evidence |
| Unsafe consumption of APIs | Implemented | `app/security/passwords.py`, `app/security/turnstile.py` | `tests/test_passwords.py`, `tests/test_config.py` | HIBP sends only SHA-1 prefixes with padding; Turnstile endpoint is configured and token data is redacted | Add allowlists for future third-party integrations |

## CIS Controls v8

| Control area | Status | Relevant files | Relevant tests | Current evidence | Remaining gaps / follow-up |
| --- | --- | --- | --- | --- | --- |
| Account and access management | Partially implemented | `app/admin/services.py`, `docs/security/admin-and-staging-zero-trust-access.md` | `tests/test_admin_staff_invites.py`, `tests/test_zero_trust_access_boundary.py` | Staff invites, root-admin TOTP, admin isolation, private-access runbook | Live Cloudflare/Tailscale state needs operator verification |
| Data protection | Partially implemented | `docs/security/privacy-and-pdpa.md`, `docs/security/data-retention-and-deactivation.md`, `ops/backups/*` | `tests/test_privacy_pdpa_docs.py`, `tests/test_backup_security.py` | Encrypted backups, personal-data inventory, and retention/deactivation expectations are documented | Complete retention/disposal scheduler remains open |
| Secure configuration | Partially implemented | `config.py`, `ops/ssh/99-sitbank-hardening.conf`, `ops/nginx/*` | `tests/test_config.py`, `tests/test_ec2_ssh_hardening_docs.py`, `tests/test_deployment.py` | Production guard, Nginx TLS policy, SSH drop-in template | Host firewall/security-group rollout needs operator action |
| Audit log management | Partially implemented | `app/security/audit.py`, `app/security/alerts.py` | `tests/test_audit_alerting.py` | HMAC chain, append-only triggers, alerts | Admin audit viewer UI is open |
| Vulnerability management | Implemented | `.github/workflows/ci-deploy.yml`, `.github/dependabot.yml`, `scripts/ci-local` | `tests/test_deployment.py` | Dependency scans, image scans, CodeQL, Bandit, Dependabot policy | Keep scanner scope under review |

## NIST SP 800-63B

| Control area | Status | Relevant files | Relevant tests | Current evidence | Remaining gaps / follow-up |
| --- | --- | --- | --- | --- | --- |
| Memorized secrets | Partially implemented | `app/security/passwords.py`, `config.py` | `tests/test_passwords.py`, `tests/test_config.py`, `tests/test_production_guard.py` | Production 15-character minimum, common-password screening, HIBP k-anonymity, PBKDF2+pepper | Previous-password history is open |
| Authenticator lifecycle | Implemented | `app/auth/services.py`, `app/auth/recovery_codes.py` | `tests/test_mfa_lifecycle.py`, `tests/test_password_reset.py` | TOTP enrollment/replacement, replay prevention, recovery-code hashing, fresh step-up for regeneration | None currently tracked |
| Session management | Partially implemented | `app/security/sessions.py`, `config.py` | `tests/test_session_management.py`, `tests/test_session_absolute_lifetime.py` | Idle timeout, absolute lifetime, secure cookies, reauth on risk drift | Active-session cap and device-bound proof are open defense-in-depth items |

## MAS TRM / MAS Cyber Hygiene

| Control area | Status | Relevant files | Relevant tests | Current evidence | Remaining gaps / follow-up |
| --- | --- | --- | --- | --- | --- |
| Access control and MFA | Partially implemented | `docs/security/admin-and-staging-zero-trust-access.md`, `app/admin/services.py` | `tests/test_admin_staff_invites.py`, `tests/test_zero_trust_access_boundary.py` | Admin TOTP, private-access design, staff invite lifecycle | Live private-access state requires operator verification |
| Patch and vulnerability management | Implemented | `.github/dependabot.yml`, `.github/workflows/ci-deploy.yml` | `tests/test_deployment.py` | Dependabot review, dependency scans, Trivy gates, pinned images | Continue review cadence |
| Security monitoring and incident handling | Implemented | `app/security/alerts.py`, `docs/OPERATIONS.md`, `docs/security/incident-response.md` | `tests/test_audit_alerting.py`, `tests/test_privacy_pdpa_docs.py` | Alert timer, audit chain, operational monitoring, and incident response workflows are documented | Keep live response evidence outside public issues |
| Data and backup resilience | Implemented | `ops/backups/*`, `ops/deploy/sitbank-database-cutover` | `tests/test_backup_security.py` | Encrypted backup helper and restore preflight | Real backup schedules/restore exercises are operator evidence |

## CWE Top 25

| Weakness family | Status | Relevant files | Relevant tests | Current evidence | Remaining gaps / follow-up |
| --- | --- | --- | --- | --- | --- |
| Injection | Implemented | SQLAlchemy services, WTForms/Marshmallow schemas | `tests/test_banking_transaction_security.py`, `tests/test_owasp_regressions.py` | Structured queries and payload allowlists | Add tests for new query surfaces |
| Cross-site scripting | Implemented | Jinja templates | `tests/test_authenticated_portal_ui.py` | Autoescape and no user-controlled `|safe` regression | None currently tracked |
| Authentication/session weaknesses | Partially implemented | `app/auth/services.py`, `app/security/sessions.py` | `tests/test_auth_registration_login.py`, `tests/test_session_management.py` | Generic auth, server-side sessions, HMAC integrity | Password history and active-session cap are open |
| Broken access control/IDOR | Implemented | `app/banking/routes.py`, `app/admin/routes.py` | `tests/test_payee_management_security.py`, `tests/test_admin_route_inventory_security.py` | Payee ownership and admin route inventories | None currently tracked |
| Cryptographic misuse | Partially implemented | `app/security/crypto.py`, `ops/nginx/sitbank-tls-policy.conf`, `ops/backups/*` | `tests/test_mfa_envelope_crypto.py`, `tests/test_backup_security.py` | AEAD envelope encryption, TLS policy, encrypted backups | Live TLS/host proof remains operator evidence |
