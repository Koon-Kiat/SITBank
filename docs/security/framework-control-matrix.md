# Framework Control Matrix

This matrix maps SITBank's current repository evidence to common security
frameworks. It is not a certification claim; it is an evidence index for code,
tests, deployment controls, governance documents, and follow-up work. Current
open items are tracked only in `docs/security/security-gap-register.md`; role
ownership and review cadence are defined in
`docs/security/security-governance.md`.

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
| Session management | Partially implemented | `app/security/sessions.py`, `config.py` | `tests/test_session_management.py`, `tests/test_session_absolute_lifetime.py`, `tests/test_session_risk_binding.py`, `tests/test_db_session_integrity.py` | PostgreSQL-backed opaque sessions, HMAC-wrapped payloads, idle expiry, absolute lifetime, revocation, inventory, customer/admin context-risk handling | Optional active-session cap and cryptographic device-bound proof are open |
| Access control | Implemented | `app/web/routes.py`, `app/banking/routes.py`, `app/admin/routes.py`, `app/admin/services.py` | `tests/test_route_inventory_security.py`, `tests/test_admin_route_inventory_security.py`, `tests/test_admin_dashboard_role_separation.py`, `tests/test_payee_management_security.py` | Customer/admin route inventories, admin isolation, staff/admin/root dashboard separation, direct banking MFA gate, payee ownership tests | None currently tracked for core route authorization |
| Input validation and output encoding | Implemented | `app/auth/forms.py`, `app/banking/forms.py`, `app/auth/schemas.py`, templates | `tests/test_banking_transaction_security.py`, `tests/test_authenticated_portal_ui.py`, `tests/test_owasp_regressions.py` | WTForms/Marshmallow/service validation, template autoescape, no user-controlled `|safe` | Continue adding tests for new input surfaces |
| Cryptography and secrets | Implemented | `app/security/crypto.py`, `app/security/session_hmac.py`, `.github/workflows/gitleaks.yml`, `.gitleaks.toml`, `ops/security/scan_repository_secrets.py`, `ops/nginx/sitbank-tls-policy.conf` | `tests/test_mfa_envelope_crypto.py`, `tests/test_config.py`, `tests/test_gitleaks_workflow.py`, `tests/test_secret_scanner.py` | MFA envelope encryption, session/audit HMAC, root-managed secret files, and complementary custom plus Gitleaks 8.30.1 full Git history scanning with redacted output | Live TLS evidence remains deployed-endpoint verification |
| Logging and monitoring | Implemented | `app/security/audit.py`, `app/security/alerts.py`, `app/ops/commands.py`, `app/admin/routes.py`, `app/admin/services.py` | `tests/test_audit_alerting.py`, `tests/test_audit_metadata_sanitization.py`, `tests/test_admin_audit_viewer.py`, `tests/test_admin_dashboard_operations.py` | Sanitized audit rows, HMAC hash chain, alert dedupe and delivery sanitization, admin/root read-only audit viewer with validated filters and redacted detail, and read-only alert review UI | Keep live operational evidence outside public issues |

## OWASP Top 10 2025

| Control area | Status | Relevant files | Relevant tests | Current evidence | Remaining gaps / follow-up |
| --- | --- | --- | --- | --- | --- |
| Broken access control | Implemented | `app/banking/routes.py`, `app/admin/routes.py`, `app/admin/separation.py`, `app/admin/services.py` | `tests/test_payee_management_security.py`, `tests/test_admin_route_inventory_security.py`, `tests/test_admin_dashboard_role_separation.py`, `tests/test_admin_isolation.py` | Ownership filters, route inventories, admin/customer isolation, staff/admin/root separation of duties, staff self-action guard | None currently tracked for implemented route surfaces |
| Cryptographic failures | Partially implemented | `ops/nginx/sitbank-tls-policy.conf`, `ops/deploy/verify-certbot-host-state`, `app/security/crypto.py`, `ops/backups/*` | `tests/test_mfa_envelope_crypto.py`, `tests/test_backup_security.py`, `tests/test_deployment.py` | TLS policy, local certificate lifecycle checks, AES-GCM MFA envelopes, PBKDF2+pepper, encrypted backups | Live endpoint and renewal dry-run evidence remains operational |
| Injection and SSRF | Implemented | `app/banking/services.py`, `app/auth/routes.py`, `app/security/passwords.py` | `tests/test_banking_transaction_security.py`, `tests/test_owasp_regressions.py` | SQLAlchemy query construction, payload allowlists, open-redirect regression tests, fixed HIBP endpoint | Add allowlist tests for any future outbound integrations |
| Security misconfiguration | Partially implemented | `config.py`, `app/security/production_guard.py`, `ops/nginx/*`, `ops/tailscale/*`, `ops/deploy/verify-tailscale-admin-access`, `.github/workflows/tailscale-private-admin-verify.yml` | `tests/test_production_guard.py`, `tests/test_deployment.py`, `tests/test_zero_trust_access_boundary.py`, `tests/test_tailscale_admin_access.py`, `tests/test_tailscale_admin_automation.py`, `tests/test_tailscale_ci_tailnet_workflow.py` | Production fail-closed guard, Docker hardening, Nginx TLS, loopback binding, confirmation-gated private Serve provisioning, EC2-local Serve/Funnel/listener verification, and protected reachability verification | EC2 SSH/UFW/security-group hardening is deferred; live Cloudflare policy and Tailscale ACL/device/operator state remain operator-owned |
| Vulnerable and outdated components | Partially implemented | `.github/workflows/ci-deploy.yml`, `scripts/ci-local`, lockfiles, `ops/container/smoke-test.sh` | `tests/test_deployment.py`, `tests/test_secret_scanner.py`, `tests/test_dast_helper_security.py` | Hash-locked Python deps, dependency review, pip-audit, Trivy, CodeQL, Bandit, and release/scheduled authenticated DAST where the DAST cookie is not passed as a raw process argument | Ordinary-PR authenticated DAST remains a policy tradeoff |
| Identification and authentication failures | Partially implemented | `app/auth/services.py`, `app/auth/password_reset.py` | `tests/test_password_reset.py`, `tests/test_account_security_actions.py` | Reset token exchange, MFA onboarding, session revocation, generic errors | Full previous-password history remains open |
| Logging and monitoring failures | Implemented | `docs/security/audit-and-alerting.md`, `docs/security/incident-response.md`, `app/security/alerts.py`, `app/admin/routes.py`, `app/admin/services.py` | `tests/test_audit_alerting.py`, `tests/test_privacy_pdpa_docs.py`, `tests/test_admin_audit_viewer.py`, `tests/test_admin_dashboard_operations.py` | Audit hash chain, alert scheduler, sanitized delivery, incident workflows, hardened admin/root audit review UI, and read-only alert review route | Keep live response evidence outside public issues |

## NIST SP 800-218 SSDF

| Control area | Status | Relevant files | Relevant tests | Current evidence | Remaining gaps / follow-up |
| --- | --- | --- | --- | --- | --- |
| Prepare the organization | Implemented | `docs/security/security-governance.md`, `docs/security/security-gap-register.md`, `docs/security/framework-control-matrix.md`, `docs/security/design-risk-register.md` | `tests/test_security_governance_docs.py`, `tests/test_framework_control_docs.py` | Role-based ownership, recurring review cadence, accepted-risk handling, off-repo ownership, remediation tracking, and stale-documentation prevention are documented | Keep owner/status/review fields current during milestone and release reviews |
| Protect the software | Implemented | `.github/workflows/ci-deploy.yml`, `ops/deploy/*`, `Dockerfile` | `tests/test_deployment.py` | Pinned actions/images, signed digests, protected main deployment, restricted wrappers | OIDC + SSM migration remains optional follow-up |
| Produce well-secured software | Implemented | `app/`, `config.py`, `ops/security/*`, `.github/workflows/gitleaks.yml`, `.github/workflows/sonarqube.yml`, `scripts/ci-local` | Full pytest, CodeQL, Bandit, SonarQube, dependency tests, `tests/test_gitleaks_workflow.py`, `tests/test_ci_local.py`, `tests/test_sonarqube_workflow.py` | Secure coding controls, route inventories, production guard, custom secret scanner, checksum-verified Gitleaks full-history scanning, strict local Docker/Compose mode, reporting-only coverage and maintainability dashboard, and one sticky informational PR summary for trusted internal PRs | Continue adding tests for new features; SonarQube gate remains non-blocking during baseline triage |
| Respond to vulnerabilities | Implemented | `SECURITY.md`, `docs/OPERATIONS.md`, `docs/security/incident-response.md`, `.github/dependabot.yml` | `tests/test_privacy_pdpa_docs.py`, `tests/test_deployment.py` | Dependabot review-only policy, vulnerability exception policy, monitoring commands, and incident workflows are documented | Keep incident playbooks updated after exercises |

## OWASP SAMM

| Control area | Status | Relevant files | Relevant tests | Current evidence | Remaining gaps / follow-up |
| --- | --- | --- | --- | --- | --- |
| Governance | Implemented | `docs/security/security-governance.md`, `docs/security/security-gap-register.md`, `docs/security/design-risk-register.md`, `docs/CONTRIBUTION_MESSAGE_POLICY.md` | `tests/test_security_governance_docs.py`, `tests/test_framework_control_docs.py`, `tests/test_deployment.py` | Gap register, design-risk owner fields, role-based review cadence, commit/PR policy, and release gates | Off-repo owner evidence still has to be reviewed from the external system that owns it |
| Design | Implemented | `docs/security/threat-model.md`, `docs/security/design-risk-register.md`, `docs/security/access-control.md`, `docs/security/cryptography-and-authentication.md` | `tests/test_threat_model_docs.py`, `tests/test_route_inventory_security.py`, `tests/test_admin_route_inventory_security.py` | Threat model, design risk register, access-control docs, and crypto architecture docs | Keep model/register updated when architecture changes |
| Implementation | Implemented | `app/`, `ops/security/*`, `.github/workflows/gitleaks.yml`, `.gitleaks.toml`, lockfiles | `tests/test_owasp_regressions.py`, `tests/test_deployment.py`, `tests/test_gitleaks_workflow.py`, `tests/test_secret_scanner.py` | Input validation, output encoding, SAST, dependency locks, custom secret scanning, and redacted Gitleaks full-history scanning | Continue feature-specific tests |
| Verification | Partially implemented | `tests/`, `.github/workflows/ci-deploy.yml`, `.github/workflows/gitleaks.yml`, `.github/workflows/sonarqube.yml`, `.github/workflows/tailscale-private-admin-verify.yml`, `scripts/ci-local` | `tests/test_deployment.py`, `tests/test_dast_helper_security.py`, `tests/test_gitleaks_workflow.py`, `tests/test_ci_local.py`, `tests/test_sonarqube_workflow.py`, `tests/test_tailscale_ci_tailnet_workflow.py` | Full pytest, reporting-only SonarQube, custom and Gitleaks secret scans, DAST, smoke tests, strict local mode, and protected private-tailnet reachability verification | Authenticated DAST on ordinary PRs remains a policy tradeoff; live Tailscale policy/device evidence remains operator-owned |
| Operations | Partially implemented | `docs/OPERATIONS.md`, `ops/cloudflare/provision-staging-access`, `ops/tailscale/*`, `ops/deploy/verify-tailscale-admin-access`, `.github/workflows/cloudflare-access-verify.yml`, `.github/workflows/tailscale-private-admin-verify.yml` | `tests/test_deployment.py`, `tests/test_cloudflare_access_automation.py`, `tests/test_zero_trust_access_boundary.py`, `tests/test_tailscale_admin_access.py`, `tests/test_tailscale_admin_automation.py`, `tests/test_tailscale_ci_tailnet_workflow.py` | Alert/backup tooling, provider verification, origin enforcement, private admin provisioning/runbook, host preflight, and required protected reachability gate exist | Live EC2 SSH/UFW, IdP, Tailscale ACL/device/operator membership, and cloud state still need operator evidence |

## Singapore PDPA

| Control area | Status | Relevant files | Relevant tests | Current evidence | Remaining gaps / follow-up |
| --- | --- | --- | --- | --- | --- |
| Protection obligation | Implemented | `docs/security/privacy-and-pdpa.md`, `app/security/audit.py`, `config.py`, `ops/backups/*` | `tests/test_privacy_pdpa_docs.py`, `tests/test_audit_metadata_sanitization.py`, `tests/test_backup_security.py` | Personal-data categories, minimization, redaction, encrypted backups, root-managed secret files, and TLS policy are documented/tested | Live host controls need operator evidence |
| Retention controls | Partially implemented | `docs/security/data-retention-and-deactivation.md`, `docs/OPERATIONS.md`, `app/security/state_cleanup.py` | `tests/test_privacy_pdpa_docs.py`, `tests/test_deployment.py` | Audit retention, deactivation/deletion/anonymization distinction, and selected security-state cleanup are documented | Complete retention/disposal scheduler remains open |
| Access/correction and accountability | Implemented | `docs/security/privacy-and-pdpa.md`, `app/auth/services.py`, `docs/security/audit-and-alerting.md` | `tests/test_privacy_pdpa_docs.py`, `tests/test_account_security_actions.py`, `tests/test_audit_alerting.py` | Account update expectations, audit trail, and breach escalation path are documented | Continue documenting new data categories as features are added |

## OWASP API Security Top 10

| Control area | Status | Relevant files | Relevant tests | Current evidence | Remaining gaps / follow-up |
| --- | --- | --- | --- | --- | --- |
| Object and function authorization | Implemented | `app/banking/routes.py`, `app/auth/routes.py`, `app/admin/routes.py` | `tests/test_payee_management_security.py`, `tests/test_route_inventory_security.py`, `tests/test_admin_route_inventory_security.py` | BOLA/BFLA controls through ownership filters, route inventories, CSRF and MFA gates | None currently tracked for implemented API routes |
| Authentication | Implemented | `app/auth/services.py`, `app/security/sessions.py` | `tests/test_auth_registration_login.py`, `tests/test_session_management.py` | Generic auth, TOTP, recovery codes, server-side sessions | Password history remains open |
| Object property authorization and mass assignment | Implemented | `app/auth/forms.py`, `app/admin/services.py`, `app/banking/schemas.py` | `tests/test_owasp_regressions.py`, `tests/test_admin_staff_invites.py` | Forged privileged fields rejected; URL-like mass assignment blocked | Continue coverage for new APIs |
| Resource consumption and business flows | Partially implemented | `app/security/rate_limits.py`, route decorators, `.github/workflows/ci-deploy.yml`, `ops/container/smoke-test.sh` | `tests/test_route_inventory_security.py`, `tests/test_audit_alerting.py`, `tests/test_dast_helper_security.py` | Rate-limit inventory and alerting exist; ZAP loads the authenticated-cookie replacer from a restricted file during release/scheduled DAST | Authenticated DAST PR coverage remains a tradeoff |
| Security misconfiguration and inventory | Partially implemented | `tests/test_route_inventory_security.py`, `tests/test_admin_route_inventory_security.py` | Same | Generated route inventories exist | Live EC2 firewall and security-group posture need operator evidence |
| Unsafe consumption of APIs | Implemented | `app/security/passwords.py`, `app/security/turnstile.py` | `tests/test_passwords.py`, `tests/test_config.py` | HIBP sends only SHA-1 prefixes with padding; Turnstile endpoint is configured and token data is redacted | Add allowlists for future third-party integrations |

## CIS Controls v8

| Control area | Status | Relevant files | Relevant tests | Current evidence | Remaining gaps / follow-up |
| --- | --- | --- | --- | --- | --- |
| Account and access management | Partially implemented | `app/admin/services.py`, `app/security/cloudflare_access.py`, `ops/cloudflare/provision-staging-access`, `ops/deploy/verify-cloudflare-origin-pull-ca`, `docs/security/admin-and-staging-zero-trust-access.md` | `tests/test_admin_staff_invites.py`, `tests/test_admin_dashboard_role_separation.py`, `tests/test_cloudflare_access_automation.py`, `tests/test_cloudflare_access_staging.py`, `tests/test_cloudflare_origin_pull_ca.py`, `tests/test_zero_trust_access_boundary.py` | Staff invites, root-admin TOTP, staff/admin/root role separation, admin isolation, narrow Access policy/DNS automation, JWT assertion enforcement, pinned origin-pull trust, and live boundary verification | Live IdP membership and Tailscale state need operator verification |
| Data protection | Partially implemented | `docs/security/privacy-and-pdpa.md`, `docs/security/data-retention-and-deactivation.md`, `ops/backups/*` | `tests/test_privacy_pdpa_docs.py`, `tests/test_backup_security.py` | Encrypted backups, personal-data inventory, and retention/deactivation expectations are documented | Complete retention/disposal scheduler remains open |
| Secure configuration | Partially implemented | `config.py`, `ops/nginx/*`, `ops/deploy/verify-certbot-host-state`, `ops/deploy/verify-cloudflare-origin-pull-ca`, `ops/security/cloudflare-origin-pull-ca-allowlist.json`, `docs/security/security-gap-register.md` | `tests/test_config.py`, `tests/test_cloudflare_origin_pull_ca.py`, `tests/test_deployment.py` | Production guard, pinned Nginx TLS policy, fail-closed local certificate checks, reviewed origin-pull CA pinning, and deferred EC2 SSH hardening gap are documented | Host SSH/firewall/security-group hardening remains deferred |
| Audit log management | Implemented | `app/security/audit.py`, `app/security/alerts.py`, `app/admin/routes.py`, `app/admin/services.py` | `tests/test_audit_alerting.py`, `tests/test_admin_audit_viewer.py`, `tests/test_admin_dashboard_operations.py` | HMAC chain, append-only triggers, alerts, admin/root read-only audit viewer with safe query validation/redaction, and safe alert review | Keep live audit-review evidence outside public issues |
| Vulnerability management | Implemented | `.github/workflows/ci-deploy.yml`, `.github/workflows/sonarqube.yml`, `.github/dependabot.yml`, `scripts/ci-local` | `tests/test_deployment.py`, `tests/test_sonarqube_workflow.py`, `tests/test_sonarqube_pr_comment_workflow.py` | Dependency scans, image scans, CodeQL, Bandit, reporting-only SonarQube dashboard and trusted-PR summary, Dependabot policy | Keep scanner scope and SonarQube baseline under review; any blocking gate or inline-comment rollout requires separate review |

## NIST SP 800-63B

| Control area | Status | Relevant files | Relevant tests | Current evidence | Remaining gaps / follow-up |
| --- | --- | --- | --- | --- | --- |
| Memorized secrets | Partially implemented | `app/security/passwords.py`, `config.py` | `tests/test_passwords.py`, `tests/test_config.py`, `tests/test_production_guard.py` | Production 15-character minimum, common-password screening, HIBP k-anonymity, PBKDF2+pepper | Previous-password history is open |
| Authenticator lifecycle | Implemented | `app/auth/services.py`, `app/auth/recovery_codes.py` | `tests/test_mfa_lifecycle.py`, `tests/test_password_reset.py` | TOTP enrollment/replacement, replay prevention, recovery-code hashing, fresh step-up for regeneration | None currently tracked |
| Session management | Partially implemented | `app/security/sessions.py`, `config.py` | `tests/test_session_management.py`, `tests/test_session_absolute_lifetime.py`, `tests/test_session_risk_binding.py` | Idle timeout, absolute lifetime, secure cookies, customer reauth/revocation and strict admin revocation on risk drift | Active-session cap remains needs-triage; cryptographic device-bound proof is an accepted defense-in-depth item, with Tailscale as the admin private boundary |

## MAS TRM / MAS Cyber Hygiene

| Control area | Status | Relevant files | Relevant tests | Current evidence | Remaining gaps / follow-up |
| --- | --- | --- | --- | --- | --- |
| Access control and MFA | Partially implemented | `docs/security/admin-and-staging-zero-trust-access.md`, `.github/workflows/tailscale-private-admin-verify.yml`, `ops/cloudflare/provision-staging-access`, `ops/tailscale/*`, `ops/deploy/verify-tailscale-admin-access`, `app/security/cloudflare_access.py`, `app/admin/services.py` | `tests/test_admin_staff_invites.py`, `tests/test_cloudflare_access_automation.py`, `tests/test_zero_trust_access_boundary.py`, `tests/test_tailscale_admin_access.py`, `tests/test_tailscale_admin_automation.py`, `tests/test_tailscale_ci_tailnet_workflow.py` | Admin TOTP/invites, Cloudflare enforcement, private Tailscale provisioning, host posture checks, dual-mode protected reachability, and least-privilege policy guidance | Live IdP membership and Tailscale membership/ACL/device state require operator verification |
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
| Cryptographic misuse | Partially implemented | `app/security/crypto.py`, `ops/nginx/sitbank-tls-policy.conf`, `ops/deploy/verify-certbot-host-state`, `ops/backups/*` | `tests/test_mfa_envelope_crypto.py`, `tests/test_backup_security.py`, `tests/test_deployment.py` | AEAD envelope encryption, pinned TLS policy, local certificate expiry/SAN checks, encrypted backups | Live TLS and renewal dry-run proof remains operator evidence |
