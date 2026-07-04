# Access Control

This document records the access-control model implemented in the SITBank
repository. It distinguishes implemented runtime enforcement from test
coverage notes and service-only flows.
Framework coverage and current follow-up items are centralized in
`docs/security/governance/framework-control-matrix.md` and
`docs/security/governance/security-gap-register.md`.
Privacy/deactivation expectations for customer and staff/admin records are in
`docs/security/governance/privacy-and-pdpa.md`,
`docs/security/governance/data-retention-and-deactivation.md`, and
`docs/security/governance/incident-response.md`.

Category: [Security architecture](../README.md#architecture).

## Access-Control Model

SITBank uses role, account-state, MFA-state, and ownership checks. The primary
role field is `User.account_type` in `app/models.py`, constrained to:

```text
customer, staff, admin, root_admin
```

Customer and admin functionality are separated at application-factory level:

| Runtime | Entry point | Registered surface | Evidence |
| --- | --- | --- | --- |
| Customer app | `wsgi.py` / `create_app(app_mode="customer")` | Auth, banking, web, main routes | `app/__init__.py`, `app/auth/routes.py`, `app/banking/routes.py`, `app/web/routes.py` |
| Admin app | `admin_wsgi.py` / `create_app(app_mode="admin")` | Admin routes only | `app/__init__.py`, `app/admin/routes.py` |

The customer app rejects staff/admin account types during customer login in
`app/auth/services.py`. Customer registration and customer profile email
changes also reject the configured admin workplace domains through
`app/security/identity_policy.py`. The admin app accepts only staff account
types with active status, an approved admin workplace email domain, verified
workplace email, password authentication, and TOTP in `app/admin/services.py`.

Tests:

| Test | Coverage |
| --- | --- |
| `tests/test_admin_isolation.py::test_customer_and_admin_apps_have_isolated_route_surfaces` | Customer/admin application route separation |
| `tests/test_admin_staff_invites.py::test_customer_registration_cannot_create_staff_or_admin_roles` | Customer self-registration cannot create privileged roles |
| `tests/test_admin_isolation.py::test_admin_auth_rejects_bad_requests_without_creating_privileged_sessions` | Admin malformed requests do not create privileged sessions |
| `tests/test_pentest_auth_bypass.py` | Negative authentication and authorization bypass cases |

## Customer Access Controls

Customer authenticated pages use request hooks and decorators to require a
valid authenticated customer session, MFA readiness where needed, and non-frozen
account state.

| Area | Enforcement | Evidence |
| --- | --- | --- |
| Dashboard and authenticated web pages | Web `before_request` gates require login and MFA onboarding completion | `app/web/routes.py`, `tests/test_dashboard.py::test_dashboard_requires_login`, `tests/test_dashboard.py::test_dashboard_requires_mfa` |
| JSON auth/account routes | Auth blueprint request hooks enforce login/MFA for protected endpoints | `app/auth/routes.py`, `tests/test_mfa_lifecycle.py::test_api_onboarding_requires_enrolled_mfa_before_authenticated_endpoints` |
| Frozen accounts | Sensitive actions call `ensure_account_not_frozen()` or are blocked by route gates | `app/auth/services.py`, `app/web/routes.py`, `tests/test_account_security_actions.py::test_account_freeze_is_durable_and_blocks_group_a_sensitive_actions` |
| Pending MFA sessions | Pending sessions cannot access authenticated resources | `tests/test_pentest_auth_bypass.py::test_pending_mfa_session_cannot_access_dashboard`, `tests/test_pentest_auth_bypass.py::test_pending_mfa_session_cannot_freeze_account` |
| Profile updates | Username changes require TOTP; profile email changes require a session-bound new-email code plus current TOTP before commit | `app/auth/services.py::update_profile_details()`, `tests/test_account_security_actions.py::test_profile_email_update_requires_email_code_and_totp_stepup` |
| Absolute session lifetime | Customer and admin sessions expire from their original authenticated timestamp, independent of activity or TOTP step-up | `app/security/sessions.py`, `tests/test_session_absolute_lifetime.py` |
| Session context risk | Coarse network or browser-family drift marks customer sessions for full reauthentication before sensitive actions; simultaneous drift revokes the session | `app/security/sessions.py`, `tests/test_session_risk_binding.py` |
| Session management | Public session refs are scoped to the current user | `app/auth/services.py::terminate_session_for_user()`, `tests/test_session_management.py::test_past_sessions_are_scoped_to_current_user` |

The route inventory in `tests/test_route_inventory_security.py` records each
customer-app route's security classification, authentication requirement, CSRF
requirement, rate-limit decision, and step-up source. The inventory is tested
against registered Flask routes by:

| Test | Coverage |
| --- | --- |
| `tests/test_route_inventory_security.py::test_route_inventory_matches_registered_flask_routes` | Inventory must match registered customer routes |
| `tests/test_route_inventory_security.py::test_route_inventory_has_complete_security_decisions` | Each route has explicit auth, CSRF, rate-limit, and step-up metadata |
| `tests/test_route_inventory_security.py::test_login_and_registration_have_method_level_security_decisions` | Method-level decisions for login and registration |

This route inventory is for the customer app surface. Admin routes use a
separate generated inventory in
`tests/test_admin_route_inventory_security.py`. The inventories are
intentionally separate so customer routes and admin routes cannot satisfy each
other's policy entries.

## Layered Rate-Limit Policy

SITBank treats abuse controls as layers. Cloudflare Access and Authenticated
Origin Pull protect the staging edge, and Cloudflare WAF/rate-limit provider
rules are defense-in-depth only when separately evidenced by sanitized provider
exports or workflow output. Repository tests do not claim live Cloudflare
WAF/rate-limit provider evidence; missing provider evidence must not remove
the Nginx, Flask-Limiter, durable backoff, CSRF, MFA, or audit controls below.

| Route family | Edge and Nginx layer | Flask and durable layer | Evidence |
| --- | --- | --- | --- |
| Customer login, registration, MFA, password reset, and manual recovery | Production uses customer auth/security Nginx rate-limit zones such as `sitbank_prod_auth`, `sitbank_prod_register`, and `sitbank_prod_security`; staging uses `sitbank_staging_login` behind Cloudflare Access and origin-pull enforcement | Route inventory requires explicit Flask-Limiter decisions; durable counters include login, registration OTP, password-reset request, manual-recovery request, and password-reset recovery-code scopes | `ops/nginx/sitbank-production-rate-limits.conf`, `ops/nginx/sitbank-staging-rate-limits.conf`, `tests/test_route_inventory_security.py`, `tests/test_rate_limit_error_ux.py` |
| Customer banking, Payee, PayUp, and session/security actions | Production uses app/security Nginx zones such as `sitbank_prod_app` and `sitbank_prod_security`; staging uses `sitbank_staging_app` behind the staging edge boundary | Unsafe banking routes are Flask-Limiter protected where listed; durable lookup scopes include `payee_lookup_failure` and `payup_lookup_failure` after TOTP | `app/banking/routes.py`, `tests/test_payee_management_security.py`, `tests/test_payup.py`, `tests/test_deployment.py` |
| Admin login, staff invite acceptance, audit, alerts, staff lifecycle, and manual recovery administration | Production admin is private through Tailscale Serve rather than public Nginx; staging admin is private operator access. Edge privacy is not a replacement for Flask controls | Admin route inventory requires explicit rate-limit decisions; admin login, invite probing, invite acceptance, TOTP, staff lifecycle, and manual recovery keep app-level rate limits/backoff and audit | `app/admin/routes.py`, `tests/test_admin_route_inventory_security.py`, `tests/test_admin_staff_invites.py`, `tests/test_tailscale_admin_access.py` |

Staging and production Nginx rate-limit files intentionally differ because
staging exercises Cloudflare Access and Authenticated Origin Pull while
production carries the public customer edge. Do not force identical zone names
or burst values unless the deployment design changes for both environments and
the associated tests and runbooks are updated.

## Banking And Payee Authorization

Payee management lives in `app/banking/routes.py` and is registered only in the
customer app. Routes use authenticated web decorators, direct banking MFA
onboarding gates, and high-risk TOTP step-up before recipient lookup or removal.

New payees are not immediately usable for transfers. The activation delay is
calculated server-side from the saved payee timestamp and
`PAYEE_COOLDOWN_SECONDS`; clients only receive display timing. Development and
test environments may keep the short default for usability, while production
configuration fails closed unless the cooldown is at least 12 hours.

| Action | Authorization control | Evidence |
| --- | --- | --- |
| List payees | Query filters by `Payee.user_id == g.current_user.id` | `app/banking/routes.py::payees()` |
| Add payee lookup | Form validation, own-account rejection, duplicate payee check scoped to current user, and `payee_add` TOTP step-up before recipient identity is looked up | `app/banking/forms.py`, `app/banking/routes.py::payees_add_submit()` |
| Add payee confirmation | Pending payee state exists only after `payee_add` TOTP authorization, is consumed before insert, recipient is reloaded from the database, and duplicate checks are repeated | `app/banking/routes.py::payees_confirm_submit()` |
| Remove payee | Payee is loaded with `id` and current `user_id`; TOTP step-up is required | `app/banking/routes.py::payees_remove_submit()` |

Local Transfer and PayUp share the banking service boundary for final ledger
movement. Pending confirmation tokens are kept raw only in the browser session;
the database stores keyed verifiers. Service execution reloads pending transfer
records, validates ownership, account state, amount, replay state, and lock
order, then writes balances and a transaction row in one required-audit-backed
commit.

| Action | Authorization control | Evidence |
| --- | --- | --- |
| Local Transfer confirmation | Payee must belong to the sender, be outside cooldown, and pass final recipient-account checks before ledger movement | `app/banking/services.py::execute_local_transfer()`, `tests/test_local_transfer_security.py` |
| PayUp phone lookup | `payup_lookup` TOTP step-up runs before recipient name disclosure; unknown, unavailable, frozen, revoked, locked, setup-pending, and self recipients return the same generic response and consume the `payup_lookup_failure` durable counter | `app/banking/routes.py::payup_submit()`, `tests/test_payup.py::test_payup_phone_lookup_requires_totp_before_name_disclosure`, `tests/test_payup.py::test_payup_phone_lookup_failures_use_durable_user_scoped_limit` |
| PayUp amount and confirmation | Daily PayUp limit resets at midnight Singapore time; confirmation recomputes the 80% step-up requirement under current usage before executing | `app/banking/services.py::payup_requires_step_up()`, `tests/test_payup.py::test_payup_confirm_rechecks_stepup_when_usage_changes_after_amount_entry` |

Transfer payload validation and future transaction-risk primitives are in
`app/banking/services.py` and `app/banking/schemas.py`, covered by
`tests/test_banking_transaction_security.py`.

Focused payee IDOR regression tests in `tests/test_payee_idor.py` prove that the
payee list is scoped to the current user and that removal lookups are scoped by
both payee ID and current user ID. Cross-user view and remove attempts return
`404` before MFA processing, do not delete the payee, and do not create a
successful `payee_remove` audit event. Broader payee enumeration, direct banking
MFA gating, duplicate/self-payee guards, and pending-payee expiry coverage
remains in `tests/test_payee_management_security.py`.

## Admin And Staff Controls

Admin/staff access uses the isolated admin runtime. Root admins are created or
rotated only by the manual allowlisted bootstrap command; staff and admin users
are invite-only after that. The implemented role hierarchy is:

```text
root_admin > admin > staff > customer
```

`staff` users receive assigned business-operation navigation only. `admin`
users can review audit logs, security alerts, and safe staff/admin status
metadata. `root_admin` users keep the most privileged invite and staff/admin
lifecycle controls. Customer accounts remain normal users and cannot satisfy
admin runtime authorization checks.

The staff/admin/root separation requirement is implemented through this
existing role model rather than by adding new roles. Current mapping:

- `staff`: bank-staff business-operation responsibility, including the
  transaction dispute review queue (`admin.disputes`, `admin.dispute_detail`,
  `admin.dispute_transition`), gated by `require_plain_staff_session` so
  `admin`/`root_admin` sessions are excluded from that queue and retain only
  audit-log oversight of dispute events. No other customer support or fraud
  review admin routes are registered yet, so the dashboard otherwise renders a
  disabled staff business-operation placeholder instead of linking to fake
  tools.
- `admin`: technical/security administration, including audit review, alert
  review, and safe staff/admin status visibility.
- `root_admin`: privileged platform administration, including staff/admin
  invites, invite revocation, staff/admin lifecycle request creation, manual
  recovery review, eligible automatic customer-lock requests, and maker-checker
  approval of selected highest-risk changes.

Server-rendered navigation is only a usability layer. Every admin route also
calls the appropriate `require_staff_session()`, `require_admin_session()`, or
`require_root_admin_session()` guard and lower-role denial is audited with
generic errors. Route inventory tests must be updated whenever that surface
changes.

| Control | Implementation evidence | Test evidence |
| --- | --- | --- |
| Generated admin route authorization inventory | `app/admin/routes.py`; explicit policy entries in `tests/test_admin_route_inventory_security.py` | `tests/test_admin_route_inventory_security.py::test_admin_route_inventory_matches_registered_flask_routes`, `tests/test_admin_route_inventory_security.py::test_admin_route_inventory_has_complete_security_decisions` |
| Staff/admin browser and JSON login requires workplace email, password, active account, approved admin email domain, verified workplace email, and TOTP | `app/admin/routes.py`, `app/admin/services.py::authenticate_admin_primary()` and `complete_admin_mfa_login()` | `tests/test_admin_dashboard_operations.py::test_admin_browser_login_and_mfa_reaches_dashboard`, `tests/test_admin_dashboard_operations.py::test_admin_json_login_contract_remains_compatible`, `tests/test_admin_dashboard_operations.py::test_admin_browser_login_rejects_staff_outside_admin_email_domains` |
| Root admin is configured by role, approved admin email domain, and an explicit non-placeholder email allowlist | `app/admin/services.py::is_root_admin()`, `app/security/identity_policy.py`, and `config.py` `ROOT_ADMIN_EMAILS` | `tests/test_admin_staff_invites.py::test_only_root_admin_with_totp_stepup_can_create_invites`, `tests/test_admin_bootstrap_root.py::test_bootstrap_root_admin_cli_rejects_non_admin_domain_allowlist_entry`, `tests/test_config.py::test_root_admin_allowlist_rejects_builtin_default_in_production`, `tests/test_production_guard.py::test_admin_validator_rejects_unsafe_root_admin_allowlists` |
| Root admin can invite only `staff` or `admin`, not `root_admin` | `StaffInvite` role constraint in `app/models.py`; role validation in `app/admin/services.py` | `tests/test_admin_staff_invites.py::test_invite_creation_validates_server_side_email_and_role_policy` |
| Staff invites use approved workplace email only and do not collect personal backup email contacts | `StaffInviteCreateSchema` in `app/admin/routes.py`; `normalize_workplace_email()` and `create_staff_invite()` in `app/admin/services.py`; `ADMIN_ALLOWED_EMAIL_DOMAINS` in `config.py` | `tests/test_admin_staff_invites.py::test_root_admin_can_create_hashed_staff_invite`, `tests/test_privileged_email_domains.py`, `tests/test_config.py::test_admin_allowed_email_domains_reject_personal_and_malformed_domains` |
| Invite acceptance rejects forged privileged fields | `_reject_forged_invite_fields()` in `app/admin/services.py` | `tests/test_admin_staff_invites.py` |
| Staff invite acceptance exposes no public setup-state metadata, binds verification to the setup browser session, limits restarts, and activates only after workplace verification and TOTP setup | `invite_info()`, `start_invite_acceptance()`, `verify_invite_acceptance()`, and `reset_staff_invite_acceptance()` | `tests/test_admin_staff_invites.py::test_invite_info_returns_minimal_metadata_and_no_store_headers`; `tests/test_admin_staff_invites.py::test_invite_acceptance_restart_limit_and_root_reset`; `tests/test_admin_staff_invites.py::test_invite_acceptance_verification_is_bound_to_start_session`; `tests/test_admin_staff_invites.py::test_staff_invite_acceptance_activates_only_after_workplace_code_and_totp` |
| Admin dashboard navigation is role-rendered and backend-enforced | `app/admin/routes.py::index()`, `app/admin/services.py::admin_navigation_for()` | `tests/test_admin_dashboard_operations.py::test_dashboard_renders_role_navigation_and_audits_access`, `tests/test_admin_dashboard_role_separation.py`, `tests/test_admin_route_inventory_security.py` |
| Admin/root audit viewer supports bounded filters, safe field search, sorting, pagination, and redacted detail display | `app/admin/routes.py::audit_logs()`, `app/admin/services.py::query_audit_events_for_admin()` | `tests/test_admin_dashboard_operations.py::test_audit_viewer_filters_bounds_and_redacts_detail_metadata`, `tests/test_admin_audit_viewer.py` |
| Admin/root alert review uses the existing report path without sending alerts on GET | `app/admin/routes.py::alerts()`, `app/security/alerts.py::build_security_alert_report()` | `tests/test_admin_dashboard_operations.py::test_alert_review_is_admin_only_and_does_not_send_alerts` |
| Admin/root manual alert delivery is POST-only, CSRF-protected, current-TOTP-gated, dedupe-aware, and audited | `app/admin/routes.py::alert_delivery()`, `app/security/alerts.py::build_security_alert_report()` | `tests/test_admin_dashboard_operations.py::test_alert_manual_delivery_browser_requires_csrf_when_enabled`, `tests/test_admin_dashboard_operations.py::test_alert_manual_delivery_reuses_builder_and_audits_delivered`, `tests/test_admin_dashboard_operations.py::test_alert_manual_delivery_respects_dedupe_and_returns_safe_json`, `tests/test_admin_dashboard_operations.py::test_alert_manual_delivery_blocks_invalid_totp`, `tests/test_admin_dashboard_operations.py::test_alert_manual_delivery_audits_configuration_failure` |
| Root-admin staff/admin lifecycle actions require maker-checker approval before final state change | `AdminActionRequest` in `app/models.py`; `app/admin/services.py::transition_staff_account_as_root_admin()` and `approve_admin_action_request_as_root_admin()` | `tests/test_admin_maker_checker.py::test_staff_lifecycle_requires_maker_checker_before_execution`, `tests/test_admin_dashboard_operations.py::test_root_manages_staff_lifecycle_with_totp_and_safe_audit` |
| Customer security unlock is root-only, limited to automatic password/MFA lock reasons, TOTP-gated, identity-separated, and executed only by a different root admin; execution clears only relevant counters, revokes customer sessions, audits, and notifies | `app/admin/services.py::request_customer_security_unlock()` and `_execute_customer_security_unlock_admin_action_request()` | `tests/test_admin_maker_checker.py::test_customer_security_unlock_requires_separate_root_and_clears_only_lock_state`, `tests/test_admin_maker_checker.py::test_customer_security_unlock_fails_closed_for_identity_overlap_and_stale_lock` |
| Staff/customer self-action guard | `app/admin/separation.py::assert_not_self_customer_action()` | `tests/test_admin_staff_invites.py::test_separation_guard_blocks_linked_staff_acting_on_own_customer`, `tests/test_admin_manual_recovery.py::test_root_admin_cannot_transition_own_customer_manual_recovery` |
| Admin session context drift | Any detected coarse-network, browser-family, or detailed User-Agent drift revokes the admin session and requires full login | `app/security/sessions.py`, `tests/test_session_risk_binding.py::test_admin_context_change_revokes_session_under_stricter_policy` |

Root-admin allowlist validation rejects placeholder/demo/default identities
including numeric shapes such as `root8`, `root-admin8`, `admin1`, and `demo1`
even when the count and workplace domain checks pass.

Root-admin maker-checker approval executes the requested operation before
marking the request `executed`. Staff lifecycle operations use the caller's
transaction boundary for the target mutation, request state, and required audit
write, so an execution error rolls back the staff-account change and records
`execution_failed` instead of leaving a partially executed approval.

Production Nginx does not publish the admin app. The admin application access
path is the Tailscale Serve URL `https://admin-sitbank.tailca101b.ts.net/`;
operators open `/login`, complete the normal Flask admin password and TOTP
controls, and then reach the dashboard. Do not enable Tailscale Funnel or
expose admin through the customer app. Customer accounts cannot authenticate to
the admin runtime.
The protected manual workflow
`.github/workflows/tailscale-private-admin-verify.yml` and the direct
production gate supply reachability evidence from a temporary GitHub-hosted
tailnet node. Their `admin-tailscale` environment uses OAuth by default, while
the manual workflow can explicitly select the optional protected
`TAILSCALE_AUTH_KEY` compatibility mode. Neither mode replaces Flask admin
login, TOTP, CSRF, route authorization, or audit logging. Production runs its
direct gate only after deployment and public TLS; normal public TLS/PR CI
remains outside the tailnet.

`ops/tailscale/` provides confirmation-gated package installation, production
Serve configuration, a verifier wrapper, and a non-secret ACL reference. The
EC2-local
`/usr/local/sbin/verify-tailscale-admin-access --mode serve` preflight
separately verifies the running node, disabled Funnel, loopback listener,
local readiness, narrow Serve mapping, Nginx absence, and private HTTPS
response without using a Tailscale credential. Live ACL, device approval, and
operator membership remain operator-reviewed state.

Manual recovery operator review is exposed only by the isolated admin app.
`GET /manual-recovery/requests` lists public-safe request summaries for root
admins. Moving a request to `under_review` remains a root-admin TOTP-gated
triage action. Approval, denial, and completion create an `AdminActionRequest`
that stores only safe metadata and an HMAC over canonical immutable fields. A
different active root admin must approve with a fresh TOTP code before the
centralized `app/auth/password_reset.py` state machine executes the final
change. Pending approval requests expire, cannot be replayed after terminal
states, and reject tampered metadata.

Session context is a risk signal, not cryptographic device binding. IP
networks and User-Agent values do not prove possession of a client-held key.
Customer policy preserves ordinary navigation after one suspicious context
change but blocks sensitive actions pending full login; admin policy revokes on
any detected drift. Context checks run after idle and absolute-lifetime
enforcement and do not replace CSRF, MFA, logout, or server-side revocation.

## High-Risk Actions And Step-Up

High-risk customer actions use `verify_high_risk_authorization()` in
`app/auth/services.py`. The current active control is TOTP.

| Action | Step-up and access control | Evidence |
| --- | --- | --- |
| Password change | Authenticated user, MFA setup, current password, TOTP step-up, revoke other sessions | `app/auth/services.py::change_password()`, `tests/test_account_security_actions.py::test_password_change_succeeds_with_recent_mfa_and_revokes_other_sessions` |
| Account details update | Authenticated user and TOTP step-up when email, phone, or other sensitive account fields change | `app/auth/services.py`, `tests/test_account_security_actions.py` |
| MFA replacement start | Fresh TOTP step-up before replacing an existing authenticator secret | `app/auth/services.py`, `tests/test_mfa_lifecycle.py::test_mfa_replacement_start_requires_fresh_mfa_stepup` |
| Recovery-code regeneration | Authenticated MFA-ready account, CSRF, fresh TOTP step-up, and audit logging before new recovery codes are issued | `app/auth/services.py::regenerate_totp_recovery_codes()`, `tests/test_mfa_lifecycle.py::test_recovery_code_regeneration_requires_fresh_totp_stepup` |
| Account freeze | Authenticated user, non-frozen state, TOTP step-up, revoke other sessions | `app/auth/services.py::freeze_own_account()`, `tests/test_account_security_actions.py::test_account_freeze_is_durable_and_blocks_group_a_sensitive_actions` |
| Protected revoke-other endpoint | Authenticated user, CSRF, and TOTP step-up; retained as a backend defense-in-depth route and not linked from the session-management page | `app/auth/routes.py::revoke_other_sessions()`, `tests/test_pentest_auth_bypass.py::test_revoke_others_requires_valid_mfa_code` |
| Terminate one session | Authenticated user, current-user ownership, public reference | `app/auth/services.py::terminate_session_for_user()`, `tests/test_pentest_auth_bypass.py::test_cannot_terminate_other_users_session` |
| Payee add confirmation | Authenticated user, pending payee state, recipient revalidation, TOTP step-up | `app/banking/routes.py::payees_confirm_submit()` |
| Payee removal | Authenticated user, payee ownership check, TOTP step-up | `app/banking/routes.py::payees_remove_submit()` |
| PayUp phone lookup | Authenticated MFA-ready customer, CSRF, rate limit, and TOTP step-up before recipient name disclosure | `app/banking/routes.py::payup_submit()`, `tests/test_payup.py` |
| PayUp confirmation near limit | Authenticated customer, pending PayUp verifier, daily-limit recomputation, and TOTP step-up when the transfer reaches at least 80% of the daily PayUp limit | `app/banking/routes.py::payup_confirm_submit()`, `tests/test_payup.py` |
| Staff invite create/revoke | Root admin session and TOTP code | `app/admin/services.py::create_staff_invite()`, `app/admin/services.py::revoke_staff_invite()` |
| Staff/admin account lifecycle | Requesting root admin session, CSRF, rate limit, TOTP step-up, no self-management, durable maker-checker request, different active root-admin approver with fresh TOTP, HMAC integrity, expiry, and safe audit metadata | `app/admin/services.py::transition_staff_account_as_root_admin()`, `app/admin/services.py::approve_admin_action_request_as_root_admin()`, `tests/test_admin_maker_checker.py` |
| Manual recovery public request | No step-up because the caller is unauthenticated; it creates only a pending request and does not unlock or mutate the account | `app/auth/password_reset.py::request_manual_recovery()`, `tests/test_password_reset.py::test_manual_recovery_request_does_not_freeze_or_unlock_account` |
| Manual recovery admin review | Root admin session in the isolated admin app | `app/admin/routes.py::manual_recovery_requests()`, `tests/test_admin_manual_recovery.py` |
| Manual recovery approval/denial/completion | Requesting root admin session, app-level Flask-WTF browser CSRF enforcement, rate limit, operator reason, TOTP step-up, durable maker-checker request, different active root-admin approver with fresh TOTP, HMAC integrity, expiry, and safe audit metadata | `app/admin/services.py::transition_manual_recovery_request_as_admin()`, `app/admin/services.py::complete_manual_recovery_request_as_admin()`, `app/admin/services.py::approve_admin_action_request_as_root_admin()`, `tests/test_admin_maker_checker.py`, `tests/test_admin_manual_recovery.py` |

## Broken Access Control Mitigations

| OWASP broken-access-control risk | Repository control |
| --- | --- |
| Relying on hidden UI controls only | Sensitive operations are enforced in routes/services, not only templates |
| Missing authentication on new routes | Customer route inventory must match registered routes and include decisions |
| CSRF on state-changing routes | Global Flask-WTF CSRF plus route inventory checks |
| IDOR on session management | Public session references are scoped to current user and raw internal ids are rejected |
| Staff/admin privilege creation through customer registration | Customer registration sets `account_type="customer"` and tests reject forged account-number and privileged fields |
| Staff acting on their own linked customer identity | `app/admin/separation.py` guard and test coverage |
| Pending MFA bypass | Pending sessions cannot access dashboard, account details, session list, MFA setup, or freeze actions |
| Frozen account bypass | Frozen accounts cannot create new login sessions or perform sensitive actions |

Admin route authorization is covered by the generated admin inventory plus
targeted admin service and flow tests. New admin routes must be added to
`tests/test_admin_route_inventory_security.py` before the suite passes.

## Staging And Admin Network Boundaries

Network boundaries complement, but do not replace, Flask authorization:

| Surface | Network boundary | Application controls that still apply |
| --- | --- | --- |
| Production customer | Public HTTPS at `sitbank.pp.ua`; `www.sitbank.pp.ua` redirects to the canonical host | Customer login, MFA onboarding, CSRF, route inventory, rate limiting |
| Staging customer | Cloudflare Access before Nginx and server-level Cloudflare Authenticated Origin Pull at Nginx | Customer login, MFA, CSRF, route inventory, rate limiting, audit logging |
| Production admin | Tailscale Serve at `https://admin-sitbank.tailca101b.ts.net/`; no public admin host or Nginx upstream; protected CI checks private reachability and the EC2 preflight checks local Serve/Funnel/listener posture | Staff/root-admin login, mandatory TOTP, CSRF, admin route inventory, admin rate limiting |
| Staging admin | Tailscale/private operator access to `127.0.0.1:5003`; no public admin host | Staff/root-admin login, mandatory TOTP, CSRF, admin route inventory, admin rate limiting |

The staging Nginx config uses Cloudflare Authenticated Origin Pulls so direct
EC2-origin requests to staging browser/app paths return `403` unless
Cloudflare's client certificate verifies successfully. Staging `/health/ready`
remains loopback-only for deployment checks. The shared default Nginx config
continues to reject unknown hostnames.
Bootstrap also validates the configured origin-pull CA before enabling the
site: safe root-owned file metadata, exactly one currently valid CA, and an
exact SHA-256 fingerprint/subject/issuer match against the repository-reviewed
allowlist are required. Trust material is never fetched during bootstrap.

`ops/cloudflare/provision-staging-access` manages and verifies the corresponding
provider-side self-hosted application, explicit email/group Allow policy,
application audience, and proxied staging DNS record. Its live verification
also checks the unauthenticated Access challenge and direct-origin denial.
The staging customer Flask app also validates the
`Cf-Access-Jwt-Assertion` RS256 signature, issuer, audience, expiry, and
optional not-before time before routing the request. Cloudflare Access remains
an outer network/identity boundary: Flask login, MFA, CSRF, ownership checks,
rate limiting and audit logging still apply. Nginx strips
Cloudflare email/service-token headers, and verified token identity remains
metadata rather than SITBank authorization input.
