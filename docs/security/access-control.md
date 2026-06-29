# Access Control

This document records the access-control model implemented in the SITBank
repository. It distinguishes implemented runtime enforcement from test
coverage notes and service-only flows.
Framework coverage and current follow-up items are centralized in
`docs/security/framework-control-matrix.md` and
`docs/security/security-gap-register.md`.
Privacy/deactivation expectations for customer and staff/admin records are in
`docs/security/privacy-and-pdpa.md`,
`docs/security/data-retention-and-deactivation.md`, and
`docs/security/incident-response.md`.

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
`app/auth/services.py`. The admin app accepts only staff account types with
active status, verified workplace email, password authentication, and TOTP in
`app/admin/services.py`.

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

| Control | Implementation evidence | Test evidence |
| --- | --- | --- |
| Generated admin route authorization inventory | `app/admin/routes.py`; explicit policy entries in `tests/test_admin_route_inventory_security.py` | `tests/test_admin_route_inventory_security.py::test_admin_route_inventory_matches_registered_flask_routes`, `tests/test_admin_route_inventory_security.py::test_admin_route_inventory_has_complete_security_decisions` |
| Staff/admin browser and JSON login requires workplace email, password, active account, verified workplace email, and TOTP | `app/admin/routes.py`, `app/admin/services.py::authenticate_admin_primary()` and `complete_admin_mfa_login()` | `tests/test_admin_dashboard_operations.py::test_admin_browser_login_and_mfa_reaches_dashboard`, `tests/test_admin_dashboard_operations.py::test_admin_json_login_contract_remains_compatible` |
| Root admin is configured by role and email allowlist | `app/admin/services.py::is_root_admin()` and `config.py` `ROOT_ADMIN_EMAILS` | `tests/test_admin_staff_invites.py::test_only_root_admin_with_totp_stepup_can_create_invites` |
| Root admin can invite only `staff` or `admin`, not `root_admin` | `StaffInvite` role constraint in `app/models.py`; role validation in `app/admin/services.py` | `tests/test_admin_staff_invites.py::test_invite_creation_validates_server_side_email_and_role_policy` |
| Invite acceptance rejects forged privileged fields | `_reject_forged_invite_fields()` in `app/admin/services.py` | `tests/test_admin_staff_invites.py` |
| Staff invite acceptance activates only after workplace verification and TOTP setup | `start_invite_acceptance()` and `verify_invite_acceptance()` | `tests/test_admin_staff_invites.py::test_staff_invite_acceptance_activates_only_after_workplace_code_and_totp` |
| Admin dashboard navigation is role-rendered and backend-enforced | `app/admin/routes.py::index()`, `app/admin/services.py::admin_navigation_for()` | `tests/test_admin_dashboard_operations.py::test_dashboard_renders_role_navigation_and_audits_access`, `tests/test_admin_route_inventory_security.py` |
| Admin/root audit viewer supports bounded filters, sorting, pagination, and safe detail display | `app/admin/routes.py::audit_logs()`, `app/admin/services.py::query_audit_events_for_admin()` | `tests/test_admin_dashboard_operations.py::test_audit_viewer_filters_bounds_and_redacts_detail_metadata` |
| Admin/root alert review uses the existing report path without sending alerts | `app/admin/routes.py::alerts()`, `app/security/alerts.py::build_security_alert_report()` | `tests/test_admin_dashboard_operations.py::test_alert_review_is_admin_only_and_does_not_send_alerts` |
| Root-admin staff/admin lifecycle actions require TOTP and audit logging | `app/admin/routes.py`, `app/admin/services.py::transition_staff_account_as_root_admin()` | `tests/test_admin_dashboard_operations.py::test_root_manages_staff_lifecycle_with_totp_and_safe_audit` |
| Staff/customer self-action guard | `app/admin/separation.py::assert_not_self_customer_action()` | `tests/test_admin_staff_invites.py::test_separation_guard_blocks_linked_staff_acting_on_own_customer` |
| Admin session context drift | Any detected coarse-network, browser-family, or detailed User-Agent drift revokes the admin session and requires full login | `app/security/sessions.py`, `tests/test_session_risk_binding.py::test_admin_context_change_revokes_session_under_stricter_policy` |

Production Nginx does not publish the admin app. The admin application access
path is the Tailscale Serve URL `https://admin-sitbank.tailca101b.ts.net/`;
operators open `/login`, complete the normal Flask admin password and TOTP
controls, and then reach the dashboard. Do not enable Tailscale Funnel or
expose admin through the customer app. Customer accounts cannot authenticate to
the admin runtime.
The protected manual/reusable workflow
`.github/workflows/tailscale-private-admin-verify.yml` supplies reachability
evidence from a temporary GitHub-hosted tailnet node. Its
`Admin-Tailscale` environment and `TAILSCALE_AUTH_KEY`
do not replace Flask admin login, TOTP, CSRF, route authorization, or audit
logging. Production calls it as a required gate only after deployment and
public production TLS verification; normal public TLS/PR CI remains outside
the tailnet.

Manual recovery operator review is exposed only by the isolated admin app.
`GET /manual-recovery/requests` lists public-safe request summaries for root
admins. `POST /manual-recovery/requests/<id>/transition` and
`POST /manual-recovery/requests/<id>/complete` require root-admin session
authorization, CSRF, rate limiting, an operator reason, and a fresh TOTP code.
The routes delegate to `app/auth/password_reset.py` so the manual recovery
state machine remains centralized.

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
| Revoke other sessions | Authenticated user and TOTP step-up | `app/auth/routes.py::revoke_other_sessions()`, `tests/test_pentest_auth_bypass.py::test_revoke_others_requires_valid_mfa_code` |
| Terminate one session | Authenticated user, current-user ownership, public reference | `app/auth/services.py::terminate_session_for_user()`, `tests/test_pentest_auth_bypass.py::test_cannot_terminate_other_users_session` |
| Payee add confirmation | Authenticated user, pending payee state, recipient revalidation, TOTP step-up | `app/banking/routes.py::payees_confirm_submit()` |
| Payee removal | Authenticated user, payee ownership check, TOTP step-up | `app/banking/routes.py::payees_remove_submit()` |
| Staff invite create/revoke | Root admin session and TOTP code | `app/admin/services.py::create_staff_invite()`, `app/admin/services.py::revoke_staff_invite()` |
| Staff/admin account lifecycle | Root admin session, CSRF, rate limit, TOTP step-up, no self-management, and safe audit metadata | `app/admin/services.py::transition_staff_account_as_root_admin()`, `tests/test_admin_dashboard_operations.py` |
| Manual recovery public request | No step-up because the caller is unauthenticated; it creates only a pending request and does not unlock or mutate the account | `app/auth/password_reset.py::request_manual_recovery()`, `tests/test_password_reset.py::test_manual_recovery_request_does_not_freeze_or_unlock_account` |
| Manual recovery admin review | Root admin session in the isolated admin app | `app/admin/routes.py::manual_recovery_requests()`, `tests/test_admin_manual_recovery.py` |
| Manual recovery transition/completion | Root admin session, CSRF, rate limit, operator reason, and TOTP step-up | `app/admin/services.py::transition_manual_recovery_request_as_admin()`, `app/admin/services.py::complete_manual_recovery_request_as_admin()`, `tests/test_admin_manual_recovery.py` |

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
| Production customer | Public HTTPS at `sitbank.duckdns.org` | Customer login, MFA onboarding, CSRF, route inventory, rate limiting |
| Staging customer | Cloudflare Access before Nginx, Cloudflare Authenticated Origin Pull at Nginx, staging Basic Auth | Customer login, MFA, CSRF, route inventory, rate limiting |
| Production admin | Tailscale Serve at `https://admin-sitbank.tailca101b.ts.net/`; public admin app routes denied; protected CI checks private reachability and public denial on demand and after production public TLS | Staff/root-admin login, mandatory TOTP, CSRF, admin route inventory, admin rate limiting |
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
rate limiting, audit logging, and Basic Auth still apply. Nginx strips
Cloudflare email/service-token headers, and verified token identity remains
metadata rather than SITBank authorization input.
