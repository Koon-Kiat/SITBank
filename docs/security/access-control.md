# Access Control

This document records the access-control model implemented in the SITBank
repository. It distinguishes implemented runtime enforcement from test gaps and
service-only flows.

## 3.1 Access-Control Model

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

## 3.2 Customer Access Controls

Customer authenticated pages use request hooks and decorators to require a
valid authenticated customer session, MFA readiness where needed, and non-frozen
account state.

| Area | Enforcement | Evidence |
| --- | --- | --- |
| Dashboard and authenticated web pages | Web `before_request` gates require login and MFA onboarding completion | `app/web/routes.py`, `tests/test_dashboard.py::test_dashboard_requires_login`, `tests/test_dashboard.py::test_dashboard_requires_mfa` |
| JSON auth/account routes | Auth blueprint request hooks enforce login/MFA for protected endpoints | `app/auth/routes.py`, `tests/test_mfa_lifecycle.py::test_api_onboarding_requires_enrolled_mfa_before_authenticated_endpoints` |
| Frozen accounts | Sensitive actions call `ensure_account_not_frozen()` or are blocked by route gates | `app/auth/services.py`, `app/web/routes.py`, `tests/test_account_security_actions.py::test_account_freeze_is_durable_and_blocks_group_a_sensitive_actions` |
| Pending MFA sessions | Pending sessions cannot access authenticated resources | `tests/test_pentest_auth_bypass.py::test_pending_mfa_session_cannot_access_dashboard`, `tests/test_pentest_auth_bypass.py::test_pending_mfa_session_cannot_freeze_account` |
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

## 3.3 Banking And Payee Authorization

Payee management lives in `app/banking/routes.py` and is registered only in the
customer app. Routes use authenticated web decorators and high-risk TOTP step-up
for payee creation confirmation and removal.

New payees are not immediately usable for transfers. The activation delay is
calculated server-side from the saved payee timestamp and
`PAYEE_COOLDOWN_SECONDS`; clients only receive display timing. Development and
test environments may keep the short default for usability, while production
configuration fails closed unless the cooldown is at least 12 hours.

| Action | Authorization control | Evidence |
| --- | --- | --- |
| List payees | Query filters by `Payee.user_id == g.current_user.id` | `app/banking/routes.py::payees()` |
| Add payee step 1 | Form validation, own-account rejection, duplicate payee check scoped to current user | `app/banking/forms.py`, `app/banking/routes.py::payees_add_submit()` |
| Add payee confirmation | Pending payee state is consumed before MFA, recipient is reloaded from the database, duplicate check is repeated, and TOTP step-up is required | `app/banking/routes.py::payees_confirm_submit()` |
| Remove payee | Payee is loaded with `id` and current `user_id`; TOTP step-up is required | `app/banking/routes.py::payees_remove_submit()` |

Transfer payload validation and future transaction-risk primitives are in
`app/banking/services.py` and `app/banking/schemas.py`, covered by
`tests/test_banking_transaction_security.py`.

Current test gap: no dedicated payee IDOR test file was found. The code uses
current-user ownership filters, and payee routes are included in the route
inventory, but there is no focused test that attempts to remove or view another
user's payee.

## 3.4 Admin And Staff Controls

Admin/staff access is invite-only and uses the admin runtime.

| Control | Implementation evidence | Test evidence |
| --- | --- | --- |
| Generated admin route authorization inventory | `app/admin/routes.py`; explicit policy entries in `tests/test_admin_route_inventory_security.py` | `tests/test_admin_route_inventory_security.py::test_admin_route_inventory_matches_registered_flask_routes`, `tests/test_admin_route_inventory_security.py::test_admin_route_inventory_has_complete_security_decisions` |
| Staff/admin login requires workplace email, password, active account, verified workplace email, and TOTP | `app/admin/services.py::authenticate_staff_primary()` and `complete_staff_mfa()` | `tests/test_admin_staff_invites.py::test_admin_login_creates_only_admin_session_cookie` |
| Root admin is configured by role and email allowlist | `app/admin/services.py::is_root_admin()` and `config.py` `ROOT_ADMIN_EMAILS` | `tests/test_admin_staff_invites.py::test_only_root_admin_with_totp_stepup_can_create_invites` |
| Root admin can invite only `staff` or `admin`, not `root_admin` | `StaffInvite` role constraint in `app/models.py`; role validation in `app/admin/services.py` | `tests/test_admin_staff_invites.py::test_invite_creation_validates_server_side_email_and_role_policy` |
| Invite acceptance rejects forged privileged fields | `_reject_forged_invite_fields()` in `app/admin/services.py` | `tests/test_admin_staff_invites.py` |
| Staff invite acceptance activates only after workplace verification and TOTP setup | `start_invite_acceptance()` and `verify_invite_acceptance()` | `tests/test_admin_staff_invites.py::test_staff_invite_acceptance_activates_only_after_workplace_code_and_totp` |
| Staff/customer self-action guard | `app/admin/separation.py::assert_not_self_customer_action()` | `tests/test_admin_staff_invites.py::test_separation_guard_blocks_linked_staff_acting_on_own_customer` |

Production Nginx currently defines an admin hostname in
`ops/nginx/sitbank-production.conf` but denies public access to the primary
admin paths with `deny all`. This keeps the admin app available for deployment
health and future controlled exposure while preventing public browser access
unless the edge policy is deliberately changed.

Manual recovery operator review is exposed only by the isolated admin app.
`GET /manual-recovery/requests` lists public-safe request summaries for root
admins. `POST /manual-recovery/requests/<id>/transition` and
`POST /manual-recovery/requests/<id>/complete` require root-admin session
authorization, CSRF, rate limiting, an operator reason, and a fresh TOTP code.
The routes delegate to `app/auth/password_reset.py` so the manual recovery
state machine remains centralized.

## 3.5 High-Risk Actions And Step-Up

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
| Manual recovery public request | No step-up because the caller is unauthenticated; it creates only a pending request and does not unlock or mutate the account | `app/auth/password_reset.py::request_manual_recovery()`, `tests/test_password_reset.py::test_manual_recovery_request_does_not_freeze_or_unlock_account` |
| Manual recovery admin review | Root admin session in the isolated admin app | `app/admin/routes.py::manual_recovery_requests()`, `tests/test_admin_manual_recovery.py` |
| Manual recovery transition/completion | Root admin session, CSRF, rate limit, operator reason, and TOTP step-up | `app/admin/services.py::transition_manual_recovery_request_as_admin()`, `app/admin/services.py::complete_manual_recovery_request_as_admin()`, `tests/test_admin_manual_recovery.py` |

## 3.6 Broken Access Control Mitigations

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

Current gap: route-level authorization is well covered for the customer app,
but admin route authorization relies on targeted admin tests and service tests
rather than a generated admin route-inventory policy.
