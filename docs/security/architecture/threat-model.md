# Threat Model

This threat model records SITBank's major assets, likely attackers, attack
paths, existing controls, evidence, remaining gaps, and priority. It should be
reviewed whenever authentication, banking, admin, deployment, audit, backup, or
privacy flows change. Review cadence and role-based ownership are defined in
`docs/security/governance/security-governance.md`.

Category: [Security architecture](../README.md#architecture).

## Scope And Assets

Primary assets:

- customer accounts, credentials, MFA state, sessions, payees, and
  banking-like records;
- staff/admin accounts, invites, sessions, and manual recovery powers;
- security audit events, alert state, hash-chain anchors, and incident reports;
- PostgreSQL data, encrypted backups, runtime secrets, deployment wrappers, and
  signed image digests;
- public EC2 edge, staging/admin private-access boundaries, and GitHub Actions
  release workflows.

## Threat Inventory

| Threat | Asset | Attacker | Attack path | Existing controls | Tests/evidence | Remaining gap | Priority |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Customer account takeover | Customer credentials, MFA, sessions | External attacker with guessed/stolen credentials | Login guessing, reset abuse, recovery-code reuse, session reuse | Generic login errors, dummy hash, rate/backoff, TOTP, recovery-code HMACs, session revocation, reset transaction exchange, password history, forced-change blocking | `tests/test_auth_registration_login.py`, `tests/test_password_reset.py`, `tests/test_session_management.py` | Continue reviewing recovery audit events and operator-driven compromise workflows | High |
| Staff/admin account takeover | Admin powers, staff invites, recovery actions | External attacker or malicious insider | Staff login abuse, invite token misuse, missing TOTP, exposed admin surface | Separate admin runtime, workplace email verification, invite-only onboarding, TOTP, root-admin checks, private access | `tests/test_admin_staff_invites.py`, `tests/test_admin_isolation.py`, `tests/test_zero_trust_access_boundary.py` | Live Tailscale/Cloudflare state needs operator verification | High |
| Admin/customer boundary bypass | Customer and admin route surfaces | Authenticated customer, staff user, or route-confusion attacker | Customer app reaches admin route, admin cookie reused in customer app, staff self-action | Separate app factories, cookie/session key separation, admin route inventory, staff self-action guard | `tests/test_admin_isolation.py`, `tests/test_admin_route_inventory_security.py`, `tests/test_admin_staff_invites.py` | None tracked for current route surfaces | High |
| Session theft or fixation | Authenticated sessions | Network/client attacker with stolen cookie | Reuse opaque cookie, tamper database payload, force pending-MFA transition | Server-side sessions, HMAC-wrapped payloads, secure cookies, idle/absolute expiry, risk drift reauth, revocation, single active session cap | `tests/test_db_session_integrity.py`, `tests/test_session_absolute_lifetime.py`, `tests/test_pentest_auth_bypass.py`, `tests/test_session_management.py` | Cryptographic device-bound proof remains an accepted defense-in-depth item | Medium |
| CSRF on state-changing routes | Customer/admin state | Cross-site attacker | Submit unsafe POST/DELETE from victim browser | Flask-WTF CSRF, route inventory, CSRF-only confirmation forms | `tests/test_route_inventory_security.py`, `tests/test_account_security_actions.py`, `tests/test_admin_route_inventory_security.py` | Continue inventory updates for new routes | Medium |
| IDOR/object-level authorization | Payees, sessions, recovery/admin records | Authenticated user targeting another user's object | Guess payee/session/request ids, remove another user's payee, view other user's sessions | Ownership filters, public session refs, direct banking MFA gate, admin root checks | `tests/test_payee_management_security.py`, `tests/test_session_management.py`, `tests/test_admin_manual_recovery.py` | None tracked for implemented payee/session/admin surfaces | High |
| MFA bypass | Customer and admin MFA state | Credentialed attacker without current TOTP | Pending-MFA session abuse, passkey/WebAuthn fallback abuse, replay accepted TOTP | TOTP baseline, replay records, no approved passkey/WebAuthn login/step-up, recovery codes as one-time TOTP factors | `tests/test_mfa_lifecycle.py`, `tests/test_pentest_auth_bypass.py`, `tests/test_password_reset.py` | TOTP remains phishing-susceptible; stronger factors are out of scope under current constraints | Medium |
| Password reset or manual recovery abuse | Reset tokens, recovery requests, MFA state | Attacker with email access or enumerating identifiers | Replay reset URL, bypass MFA, spam recovery, public request mutates account | Generic responses, selector/verifier HMAC, tokenless transaction exchange, TOTP/recovery-code requirement, pending-only manual request, admin completion with TOTP, root-admin route guards | `tests/test_password_reset.py`, `tests/test_admin_manual_recovery.py`, `tests/test_admin_dashboard_role_separation.py`, `tests/test_audit_alerting.py` | Continue reviewing recovery audit events through the hardened admin/root audit viewer | High |
| Audit log tampering | `security_audit_events`, audit anchors | DB/runtime attacker or insider | Update/delete/truncate audit rows, rewind table, alter anchor | HMAC hash chain, append-only triggers, runtime privilege verifier, anchor verify/export commands, read-only admin/root audit viewer with safe redaction | `tests/test_audit_alerting.py`, `tests/test_admin_audit_viewer.py`, `tests/test_deployment.py` | Live anchor storage and operator review cadence remain external evidence | High |
| Alert tampering or failure | Alert delivery, dedupe state, reports | Runtime attacker, webhook leak, delivery outage | Suppress alert delivery, leak webhook, poison alert payload | Sanitized report generation, final webhook sanitizer, dedupe state, systemd timer, POST-only CSRF/TOTP-gated manual delivery, and delivery failure reporting | `tests/test_audit_alerting.py`, `tests/test_deployment.py`, `tests/test_admin_dashboard_operations.py` | Alert endpoint availability remains deployment-specific | Medium |
| Backup exposure | Encrypted backups, age identities, database dumps | Host attacker, operator error, leaked backup file | Persist plaintext dump, commit dump, expose age identity, restore without checks | Encrypted backup helper, root-only temp dirs, restore preflight, secret scanner policy | `tests/test_backup_security.py`, `tests/test_deployment.py` | Backup retention/disposal automation is open | High |
| Deployment compromise | Signed image digest, EC2 wrappers, secrets | Compromised CI/job/runner or deploy key | Deploy unverified image, stale wrapper, broad sudo, leaked SSH key | Protected main release flow, Cosign signing, wrapper hash checks, restricted sudoers, environment approval | `tests/test_deployment.py`, `.github/workflows/ci-deploy.yml` | OIDC + SSM migration remains tracked as an open hardening path | High |
| CI/CD compromise | Source, workflows, packages, artifacts, protected Tailscale credential | Malicious PR/dependency/runner | Unpinned action, dependency confusion, unsafe shell/Dockerfile changes, vulnerable code, feature branch secrets, committed credential, exposed scanner session cookie, or abuse of temporary tailnet access | Pinned actions/images, dependency review, custom secret scanner, checksum-verified Gitleaks full-history scanning, repository-wide ShellCheck/Hadolint, digest-pinned local/OSS Semgrep with blocking ERROR severity, and trusted-main deployment; scanners receive no production secrets and do not mutate infrastructure; deployment and private-admin verification use separate protected-environment OAuth clients, least-privilege tags, and logout | `tests/test_deployment.py`, `tests/test_secret_scanner.py`, `tests/test_gitleaks_workflow.py`, `tests/test_static_analysis_workflows.py`, `tests/test_tailscale_admin_automation.py`, `tests/test_tailscale_ci_tailnet_workflow.py` | Branch protection, environment protection, selected credential rotation, tag/grant lifecycle, live evidence, and response to any real historical leak remain operator-owned | High |
| Public EC2 edge exposure | SSH, Nginx, Gunicorn, PostgreSQL | Internet scanner or targeted attacker | Open SSH, exposed Gunicorn/PostgreSQL, weak TLS, public admin app | Environment-specific Tailscale deploy paths, Nginx TLS policy, loopback Gunicorn, public admin denial, and deployment checks | `tests/test_deployment.py`, `tests/test_tailscale_admin_automation.py` | Operators must remove public port `22` after private deployment succeeds and retain security-group/firewall evidence; OpenSSH/UFW automation remains deferred | High |
| Staging/admin exposure | Staging app, admin app, private access state | Internet user, unapproved operator | Direct origin bypass, public admin route, Access drift, broad policy, leaked Access/provider diagnostics, unsafe host provisioning, Tailscale Funnel | Cloudflare Access/JWT checks, server-level AOP, safe reason-coded audit events, sanitized provider evidence, absent public-admin upstream, confirmation-gated fixed production Serve mapping, least-privilege ACL reference, read-only EC2 preflight, and protected private reachability | `tests/test_cloudflare_access_staging.py`, `tests/test_cloudflare_access_automation.py`, `tests/test_zero_trust_access_boundary.py`, `tests/test_tailscale_admin_automation.py`, `tests/test_tailscale_admin_access.py`, `tests/test_tailscale_ci_tailnet_workflow.py` | Operators must execute/retain sanitized host evidence and separately verify live Cloudflare policy plus Tailscale ACL/device/operator state; hostname-scoped AOP remains deferred | High |
| Data retention/privacy failure | Personal data, backups, audit records | Operator error or over-retention | Keep unnecessary data, delete evidence too early, expose health data, mishandle incident notes | PDPA inventory, retention/deactivation doc, incident response, redaction, encrypted backups | `tests/test_privacy_pdpa_docs.py`, `tests/test_audit_metadata_sanitization.py` | Automated retention/disposal jobs remain open | Medium |

## Review Triggers

Review this model when:

- new customer, banking, admin, recovery, audit, alert, backup, or deployment
  functionality is added;
- a new third-party processor or cloud service is introduced;
- the MFA/session architecture changes;
- live EC2, Cloudflare, Tailscale, AWS, or GitHub deployment boundaries change;
- an incident or tabletop exercise identifies a new abuse path.
