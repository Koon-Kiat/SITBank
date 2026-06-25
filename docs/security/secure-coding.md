# Secure Coding

This document maps SITBank's secure-coding practices to the implementation
found in the repository, with emphasis on OWASP Proactive Controls and OWASP
Top 10 risks.

## 4.1 Input Validation

The application validates input at the edge of each feature using WTForms,
Marshmallow schemas, and service-level allowlists. Sensitive server-controlled
fields are ignored or rejected rather than trusted from client payloads.

| Area | Validation evidence | Test evidence |
| --- | --- | --- |
| Customer registration and login | `app/auth/forms.py`, `app/auth/schemas.py`, `app/auth/services.py` | `tests/test_auth_registration_login.py` |
| Password policy and length limits | `app/security/passwords.py` | `tests/test_passwords.py`, `tests/test_auth_registration_login.py::test_oversized_registration_password_rejected_before_policy_processing` |
| SIT email OTP registration | `app/auth/registration_otp.py` | `tests/test_auth_registration_login.py::test_registration_otp_rejects_non_sit_email_domain`, `tests/test_auth_registration_login.py::test_registration_otp_rejects_suffix_lookalike_domain` |
| Admin invite acceptance | `app/admin/routes.py`, `app/admin/services.py` | `tests/test_admin_staff_invites.py` |
| Banking and transaction payloads | `app/banking/forms.py`, `app/banking/schemas.py`, `app/banking/services.py` | `tests/test_banking_transaction_security.py` |
| Open redirect and URL-like mass assignment | `app/auth/routes.py`, `app/web/routes.py` | `tests/test_owasp_regressions.py::test_external_next_parameter_cannot_create_an_open_redirect`, `tests/test_owasp_regressions.py::test_url_like_mass_assignment_field_is_rejected` |

Examples of server-side validation:

| Control | Evidence |
| --- | --- |
| Client-supplied account numbers are rejected during registration | `tests/test_auth_registration_login.py::test_api_registration_rejects_client_supplied_account_number` |
| Staff invite acceptance rejects privileged forged fields such as `role`, `workplace_email`, `email`, `account_type`, `customer_user_id`, and `is_admin` | `app/admin/services.py::_reject_forged_invite_fields()` |
| Transaction payloads reject server-controlled fields and unsafe business values | `tests/test_banking_transaction_security.py::test_future_transaction_payload_guardrails_reject_server_controlled_fields`, `tests/test_banking_transaction_security.py::test_public_transaction_payload_business_rules_reject_unsafe_values` |
| Route inventory records method-level auth, CSRF, rate-limit, and step-up decisions | `tests/test_route_inventory_security.py` |

## 4.2 Output Encoding

The app uses Jinja templates, which autoescape HTML by default. The repository
also contains a regression test that checks templates do not mark
user-controlled values safe.

| Control | Evidence |
| --- | --- |
| Template autoescaping by framework convention | `app/templates/` |
| No user-controlled `|safe` usage in templates | `tests/test_authenticated_portal_ui.py::test_templates_do_not_mark_user_controlled_data_safe` |
| Account details are masked in authenticated UI | `tests/test_authenticated_portal_ui.py::test_dashboard_bank_card_masks_account_details_and_loads_toggle_script` |
| Server errors do not disclose stack traces | `tests/test_owasp_regressions.py::test_server_errors_do_not_disclose_tracebacks` |

Audit and application logs sanitize sensitive metadata before storage or output.
Evidence: `app/security/audit.py`,
`tests/test_audit_metadata_sanitization.py`, and
`tests/test_audit_alerting.py::test_structured_audit_log_output_is_sanitized`.

## 4.3 Authentication And Password Coding Practices

Authentication code avoids common implementation failures:

| Practice | Evidence |
| --- | --- |
| Generic login errors | `app/auth/services.py`; `tests/test_auth_registration_login.py::test_login_errors_are_generic_for_unknown_and_wrong_password` |
| Dummy password hash for unknown users | `app/auth/services.py`; `tests/test_auth_registration_login.py::test_dummy_password_hash_tracks_current_pbkdf2_configuration` |
| Password hashing with PBKDF2-HMAC-SHA256, salt, pepper, and cost metadata | `app/security/passwords.py`; `tests/test_auth_registration_login.py::test_registration_hashes_password_with_pbkdf2` |
| Oversized passwords rejected before expensive hashing | `tests/test_auth_registration_login.py::test_oversized_login_password_uses_generic_failure_without_hashing` |
| TOTP replay prevention | `app/auth/services.py`, `app/models.py::TotpReplayRecord`; `tests/test_mfa_lifecycle.py::test_mfa_setup_stores_encrypted_secret_and_rejects_replay` |
| Recovery codes are one-time HMAC verifiers | `app/auth/recovery_codes.py`; `tests/test_password_reset.py::test_recovery_codes_are_hashed_single_use_reset_factors` |
| Active passkey flows fail closed | `app/auth/webauthn_services.py`; `tests/test_webauthn_lifecycle.py` |

Current gap: full password history is not implemented. The app rejects reuse of
the current password during change/reset but does not store previous password
hashes for history checks.

## 4.4 Session And CSRF Coding Practices

Session state is server-side, signed, and bound to a database row context.
State-changing routes use global Flask-WTF CSRF protection plus route inventory
tests.

| Practice | Evidence |
| --- | --- |
| Opaque browser session id; server-side payload | `app/security/sessions.py`, `app/models.py::ServerSideSession` |
| HMAC-signed payloads with key rotation | `app/security/session_hmac.py`, `tests/test_db_session_integrity.py` |
| Secure, HttpOnly, SameSite Strict cookies | `config.py`, `tests/test_session_management.py::test_login_sets_secure_session_cookie_and_hides_raw_session_id` |
| CSRF on unsafe customer routes | `app/extensions.py`, `app/__init__.py`, `tests/test_route_inventory_security.py::test_route_inventory_has_complete_security_decisions` |
| Explicit CSRF regression tests | `tests/test_account_security_actions.py::test_profile_post_requires_csrf_when_enabled`, `tests/test_account_security_actions.py::test_json_auth_post_requires_global_csrf_header_when_enabled` |

Current gap: there is no hard absolute maximum lifetime for fully
authenticated sessions independent of activity. Pending MFA sessions do have an
absolute age check.

## 4.5 Access-Control Coding Practices

Access control is implemented in decorators, request hooks, and services. The
customer route inventory prevents silent addition of unclassified routes.

| Practice | Evidence |
| --- | --- |
| Customer/admin app surfaces are isolated | `app/__init__.py`, `tests/test_admin_isolation.py::test_customer_and_admin_apps_have_isolated_route_surfaces` |
| Customer login rejects non-customer roles | `app/auth/services.py` |
| Admin/staff login requires active staff role, workplace email verification, and TOTP | `app/admin/services.py` |
| High-risk customer actions use TOTP step-up | `app/auth/services.py::verify_high_risk_authorization()` |
| Payee routes filter by current user id | `app/banking/routes.py` |
| Session management uses public references and ownership checks | `app/auth/services.py::terminate_session_for_user()` |

Current gap: the route-inventory matrix covers the customer app, but no
equivalent generated matrix for admin routes was found.

## 4.6 Secure Configuration

Production configuration fails closed when critical secrets or deployment
settings are missing.

| Configuration control | Evidence |
| --- | --- |
| Production secrets must come from direct env or `_FILE`, not both | `config.py::_required_env_or_file()` |
| Production secret files must resolve beneath `/run/secrets`, not symlinks | `config.py::_read_secret_file()`, `tests/test_config.py::test_production_secret_file_must_resolve_beneath_run_secrets` |
| SMTP password-reset backend requires TLS and credentials in production | `config.py`, `app/security/email.py`, `tests/test_config.py::test_production_smtp_email_requires_host_and_credentials_without_secret_leakage` |
| Password reset base URL must be HTTPS in production | `tests/test_config.py::test_password_reset_base_url_must_be_https_in_production` |
| Nginx rejects unknown hosts and redirects HTTP to HTTPS | `ops/nginx/sitbank-default.conf`, `ops/nginx/sitbank-production.conf` |
| Docker runtime drops capabilities and runs read-only as UID/GID `10001:10001` | `Dockerfile`, `compose.prod.yml`, `tests/test_deployment.py::test_dockerfile_and_compose_enforce_hardened_runtime` |
| Deployment contract keeps production and staging isolated | `compose.prod.yml`, `compose.staging.yml`, `tests/test_deployment.py::test_deployment_profiles_keep_production_and_staging_isolated` |

Current gap: Nginx does not pin an explicit `ssl_ciphers` list. The repo pins
protocols to TLS 1.2 and TLS 1.3, but cipher selection depends on deployed
Nginx/OpenSSL defaults.

## 4.7 Logging, Auditing, And Error Handling

SITBank records security-relevant events while redacting sensitive values.
Audit integrity uses an HMAC-SHA256 hash chain.

| Control | Evidence |
| --- | --- |
| Audit metadata redaction | `app/security/audit.py`, `tests/test_audit_metadata_sanitization.py` |
| Structured logs are sanitized | `tests/test_audit_alerting.py::test_structured_audit_log_output_is_sanitized` |
| Required audit writes can fail closed for critical actions | `app/security/audit.py::audit_event_required()`, `tests/test_audit_alerting.py` |
| Audit chain records, verifies, and exports anchors | `tests/test_audit_alerting.py::test_audit_hash_chain_records_verifies_and_exports_anchor` |
| Runtime database privilege verifier checks append-only audit behavior | `app/ops/db_privileges.py`, `tests/test_deployment.py::test_audit_operations_runbook_and_append_only_privileges_are_present` |
| 500 handler logs sanitized context | `tests/test_audit_alerting.py::test_500_handler_logs_sanitized_context` |

## 4.8 Dependency And Build Integrity

Dependency and build controls are implemented in scripts, lockfiles, and GitHub
Actions.

| Control | Evidence |
| --- | --- |
| Hashed Python lockfiles | `requirements.lock`, `requirements-dev.lock` |
| Lockfile policy check | `ops/security/check_dependency_locks.py`, `tests/test_deployment.py::test_dependency_manifests_have_one_hashed_lockfile_source_of_truth` |
| Vulnerability scans | `pip-audit` in `scripts/ci-local` and `.github/workflows/ci-deploy.yml`; Trivy image scans in CI |
| Static analysis | Bandit, CodeQL, actionlint, zizmor in CI/local workflows |
| Secret scanning | `ops/security/scan_repository_secrets.py`, `tests/test_secret_scanner.py` |
| Pinned GitHub Actions and images | `.github/workflows/ci-deploy.yml`, `Dockerfile`, tests in `tests/test_deployment.py` |
| Image signing and digest deployment | `.github/workflows/ci-deploy.yml`, `tests/test_deployment.py::test_workflow_builds_scans_signs_and_deploys_only_an_immutable_digest` |

## 4.9 OWASP Top 10 Mapping

| OWASP risk | SITBank controls | Gaps or notes |
| --- | --- | --- |
| A01 Broken Access Control | Customer route inventory, decorators/hooks, high-risk step-up, ownership filters, admin/customer runtime separation | Admin routes do not have an equivalent generated route-inventory matrix; payee IDOR has code-level owner filters but no dedicated IDOR test |
| A02 Cryptographic Failures | HTTPS, HSTS, AES-256-GCM MFA envelopes, HMAC session/audit integrity, PBKDF2 password storage, Docker secrets validation | No explicit Nginx cipher list; backup encryption is operationally documented but not automated in repo |
| A03 Injection | SQLAlchemy query construction, WTForms/Marshmallow validation, payload allowlists, no arbitrary URL-like mass assignment | Continue adding focused injection tests as new query surfaces are added |
| A04 Insecure Design | MFA onboarding gates, password-reset token exchange, manual recovery pending-only public request, staff invite workflow, frozen-account behavior | Manual recovery completion exists as service code but no active admin route was found |
| A05 Security Misconfiguration | Production config validation, Nginx default host rejection, Docker hardening, CSRF/Talisman defaults, deployment tests | Live host TLS cipher and certificate-renewal state must be verified outside the repo |
| A06 Vulnerable And Outdated Components | Dependabot, pip-audit, Trivy, CodeQL, hashed lockfiles, pinned Docker base image | No JavaScript package manifest was found, so npm/yarn scanning is not applicable |
| A07 Identification And Authentication Failures | Generic errors, dummy hash, rate/backoff counters, TOTP, recovery codes, reset verifier HMACs, disabled passkeys fail closed | No full password history |
| A08 Software And Data Integrity Failures | Hash-locked dependencies, pinned actions, pinned images, cosign signing, audit hash chain, migration/DB privilege tests | Verify external runner and registry trust at deployment time |
| A09 Security Logging And Monitoring Failures | Structured audit events, sanitization, alerts, append-only audit DB triggers, 500 handler logging | Alert delivery endpoint configuration is deployment-specific |
| A10 Server-Side Request Forgery | No user-supplied arbitrary URL fetch flow found; fixed HIBP range endpoint sends only SHA-1 prefixes; Turnstile verification uses configured endpoint and redacts token data | New outbound integrations should add allowlists and SSRF tests |

## 4.10 Current Secure-Coding Gaps

| Gap | Impact | Suggested remediation |
| --- | --- | --- |
| No full password history | Users can change back to an older password if it is not the current password | Add a password-history table with pepper-aware hash metadata and retention policy |
| No independent absolute lifetime for fully authenticated sessions | Long active sessions can continue as sliding sessions | Add a created-at maximum age check for authenticated sessions |
| No explicit Nginx cipher list | Cipher selection depends on host defaults | Pin approved TLS 1.2 cipher suites and verify with a live TLS scan |
| No generated admin route inventory | Admin route authorization coverage is less systematic than customer routes | Add admin-app inventory tests with auth, CSRF, rate-limit, and step-up decisions |
| Recovery-code regeneration lacks fresh step-up | An already authenticated session can regenerate backup codes without re-entering TOTP | Require `verify_high_risk_authorization()` before regeneration |
| Backup encryption not automated in repo | Database dump protection is operational rather than testable here | Add backup encryption scripts and restore/access tests if backups are in assessment scope |
