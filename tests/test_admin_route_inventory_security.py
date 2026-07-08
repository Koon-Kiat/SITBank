from __future__ import annotations

import ast
from pathlib import Path

from app import create_app
from conftest import TestConfig


UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
ADMIN_ROUTE_MODULE = Path("app/admin/routes.py")

ACCESS_DECISIONS = {"public", "public_token", "staff_session", "admin_session", "root_admin_session"}
ROLE_DECISIONS = {"none", "invite_token_holder", "staff", "admin", "root_admin"}
CSRF_DECISIONS = {"required", "not_applicable"}
RATE_LIMIT_DECISIONS = {
    "per_route",
    "admin_session",
    "edge_admin",
    "edge_health_ready",
    "not_needed_liveness",
    "not_needed_idempotent_logout",
}
STEP_UP_DECISIONS = {
    "not_required",
    "required",
    "pending_admin_mfa",
    "invite_totp_setup",
}
GUARD_DECISIONS = {
    "none",
    "require_staff_session",
    "require_plain_staff_session",
    "require_admin_session",
    "require_root_admin_session",
    "invite_token_validation",
    "pending_admin_mfa_session",
}


ADMIN_ROUTE_SECURITY_INVENTORY = {
    "admin.health_live": {
        "endpoint": "admin.health_live",
        "rule": "/health/live",
        "methods": {"GET"},
        "access": "public",
        "role": "none",
        "classification": "health",
        "csrf": "not_applicable",
        "rate_limit": "not_needed_liveness",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "none",
        "public_justification": "Liveness returns only process status for health monitors.",
    },
    "admin.health_ready": {
        "endpoint": "admin.health_ready",
        "rule": "/health/ready",
        "methods": {"GET"},
        "access": "public",
        "role": "none",
        "classification": "health",
        "csrf": "not_applicable",
        "rate_limit": "edge_health_ready",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "none",
        "public_justification": "Readiness is Flask-public but production and staging Nginx restrict it to loopback.",
    },
    "admin.csrf_token": {
        "endpoint": "admin.csrf_token",
        "rule": "/csrf-token",
        "methods": {"GET"},
        "access": "public",
        "role": "none",
        "classification": "csrf",
        "csrf": "not_applicable",
        "rate_limit": "edge_admin",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "none",
        "public_justification": "CSRF bootstrap returns only a CSRF token and no user or session data.",
    },
    "admin.index": {
        "endpoint": "admin.index",
        "rule": "/",
        "methods": {"GET"},
        "access": "staff_session",
        "role": "staff",
        "classification": "dashboard",
        "csrf": "not_applicable",
        "rate_limit": "admin_session",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "require_staff_session",
        "public_justification": "",
    },
    "admin.login_form": {
        "endpoint": "admin.login_form",
        "rule": "/login",
        "methods": {"GET"},
        "access": "public",
        "role": "none",
        "classification": "login",
        "csrf": "not_applicable",
        "rate_limit": "edge_admin",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "none",
        "public_justification": "Admin login form must be reachable before a staff session exists.",
    },
    "admin.login": {
        "endpoint": "admin.login",
        "rule": "/login",
        "methods": {"POST"},
        "access": "public",
        "role": "none",
        "classification": "login",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "state_changing": True,
        "expected_guard": "none",
        "public_justification": "Primary admin authentication must be reachable before a staff session exists.",
    },
    "admin.mfa_verify_form": {
        "endpoint": "admin.mfa_verify_form",
        "rule": "/mfa/verify",
        "methods": {"GET"},
        "access": "public",
        "role": "none",
        "classification": "mfa",
        "csrf": "not_applicable",
        "rate_limit": "edge_admin",
        "step_up": "pending_admin_mfa",
        "state_changing": False,
        "expected_guard": "pending_admin_mfa_session",
        "public_justification": "Admin MFA form is reachable only with a pending admin MFA challenge.",
    },
    "admin.mfa_verify": {
        "endpoint": "admin.mfa_verify",
        "rule": "/mfa/verify",
        "methods": {"POST"},
        "access": "public",
        "role": "none",
        "classification": "mfa",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "pending_admin_mfa",
        "state_changing": True,
        "expected_guard": "pending_admin_mfa_session",
        "public_justification": "Completes a pending admin MFA challenge before a full staff session exists.",
    },
    "admin.logout": {
        "endpoint": "admin.logout",
        "rule": "/logout",
        "methods": {"POST"},
        "access": "public",
        "role": "none",
        "classification": "logout",
        "csrf": "required",
        "rate_limit": "not_needed_idempotent_logout",
        "step_up": "not_required",
        "state_changing": True,
        "expected_guard": "none",
        "public_justification": "Logout is idempotent and clears only the caller's current admin session state.",
    },
    "admin.password_change_form": {
        "endpoint": "admin.password_change_form",
        "rule": "/account/password",
        "methods": {"GET"},
        "access": "staff_session",
        "role": "staff",
        "classification": "account_self_service",
        "csrf": "not_applicable",
        "rate_limit": "admin_session",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "require_staff_session",
        "public_justification": "",
    },
    "admin.password_change_submit": {
        "endpoint": "admin.password_change_submit",
        "rule": "/account/password",
        "methods": {"POST"},
        "access": "staff_session",
        "role": "staff",
        "classification": "account_self_service",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "state_changing": True,
        "expected_guard": "require_staff_session",
        "public_justification": "",
    },
    "admin.mfa_change_form": {
        "endpoint": "admin.mfa_change_form",
        "rule": "/account/mfa",
        "methods": {"GET"},
        "access": "staff_session",
        "role": "staff",
        "classification": "account_self_service",
        "csrf": "not_applicable",
        "rate_limit": "admin_session",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "require_staff_session",
        "public_justification": "",
    },
    "admin.mfa_change_start": {
        "endpoint": "admin.mfa_change_start",
        "rule": "/account/mfa/start",
        "methods": {"POST"},
        "access": "staff_session",
        "role": "staff",
        "classification": "account_self_service",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "state_changing": True,
        "expected_guard": "require_staff_session",
        "public_justification": "",
    },
    "admin.mfa_change_confirm": {
        "endpoint": "admin.mfa_change_confirm",
        "rule": "/account/mfa/confirm",
        "methods": {"POST"},
        "access": "staff_session",
        "role": "staff",
        "classification": "account_self_service",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "state_changing": True,
        "expected_guard": "require_staff_session",
        "public_justification": "",
    },
    "admin.customer_unfreeze_requests": {
        "endpoint": "admin.customer_unfreeze_requests",
        "rule": "/customer-unfreeze",
        "methods": {"GET"},
        "access": "staff_session",
        "role": "staff",
        "classification": "customer_self_freeze_unlock",
        "csrf": "not_applicable",
        "rate_limit": "admin_session",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "require_plain_staff_session",
        "public_justification": "",
    },
    "admin.customer_unfreeze": {
        "endpoint": "admin.customer_unfreeze",
        "rule": "/customers/<int:user_id>/unfreeze",
        "methods": {"POST"},
        "access": "staff_session",
        "role": "staff",
        "classification": "customer_self_freeze_unlock",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "state_changing": True,
        "expected_guard": "require_plain_staff_session",
        "public_justification": "",
    },
    "admin.customer_freeze_lookup_form": {
        "endpoint": "admin.customer_freeze_lookup_form",
        "rule": "/customer-freeze",
        "methods": {"GET"},
        "access": "staff_session",
        "role": "staff",
        "classification": "customer_freeze_as_staff",
        "csrf": "not_applicable",
        "rate_limit": "admin_session",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "require_plain_staff_session",
        "public_justification": "",
    },
    "admin.customer_freeze": {
        "endpoint": "admin.customer_freeze",
        "rule": "/customers/<int:user_id>/freeze",
        "methods": {"POST"},
        "access": "staff_session",
        "role": "staff",
        "classification": "customer_freeze_as_staff",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "state_changing": True,
        "expected_guard": "require_plain_staff_session",
        "public_justification": "",
    },
    "admin.invites": {
        "endpoint": "admin.invites",
        "rule": "/invites",
        "methods": {"GET"},
        "access": "root_admin_session",
        "role": "root_admin",
        "classification": "staff_invite",
        "csrf": "not_applicable",
        "rate_limit": "admin_session",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "require_root_admin_session",
        "public_justification": "",
    },
    "admin.invite_create": {
        "endpoint": "admin.invite_create",
        "rule": "/invites",
        "methods": {"POST"},
        "access": "root_admin_session",
        "role": "root_admin",
        "classification": "staff_invite",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "state_changing": True,
        "expected_guard": "require_root_admin_session",
        "public_justification": "",
    },
    "admin.invite_revoke": {
        "endpoint": "admin.invite_revoke",
        "rule": "/invites/<int:invite_id>/revoke",
        "methods": {"POST"},
        "access": "root_admin_session",
        "role": "root_admin",
        "classification": "staff_invite",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "state_changing": True,
        "expected_guard": "require_root_admin_session",
        "public_justification": "",
    },
    "admin.invite_reissue": {
        "endpoint": "admin.invite_reissue",
        "rule": "/invites/<int:invite_id>/reissue",
        "methods": {"POST"},
        "access": "root_admin_session",
        "role": "root_admin",
        "classification": "staff_invite",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "state_changing": True,
        "expected_guard": "require_root_admin_session",
        "public_justification": "",
    },
    "admin.invite_reset_acceptance": {
        "endpoint": "admin.invite_reset_acceptance",
        "rule": "/invites/<int:invite_id>/reset-acceptance",
        "methods": {"POST"},
        "access": "root_admin_session",
        "role": "root_admin",
        "classification": "staff_invite",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "state_changing": True,
        "expected_guard": "require_root_admin_session",
        "public_justification": "",
    },
    "admin.staff_accounts": {
        "endpoint": "admin.staff_accounts",
        "rule": "/staff",
        "methods": {"GET"},
        "access": "admin_session",
        "role": "admin",
        "classification": "staff_account",
        "csrf": "not_applicable",
        "rate_limit": "admin_session",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "require_admin_session",
        "public_justification": "",
    },
    "admin.staff_account_deactivate": {
        "endpoint": "admin.staff_account_deactivate",
        "rule": "/staff/<int:user_id>/deactivate",
        "methods": {"POST"},
        "access": "root_admin_session",
        "role": "root_admin",
        "classification": "staff_account",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "state_changing": True,
        "expected_guard": "require_root_admin_session",
        "public_justification": "",
    },
    "admin.customer_security_locks": {
        "endpoint": "admin.customer_security_locks",
        "rule": "/customer-security-locks",
        "methods": {"GET"},
        "access": "root_admin_session",
        "role": "root_admin",
        "classification": "customer_security_unlock",
        "csrf": "not_applicable",
        "rate_limit": "admin_session",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "require_root_admin_session",
        "public_justification": "",
    },
    "admin.customer_security_unlock_request": {
        "endpoint": "admin.customer_security_unlock_request",
        "rule": "/customers/<int:user_id>/security-unlock-requests",
        "methods": {"POST"},
        "access": "root_admin_session",
        "role": "root_admin",
        "classification": "customer_security_unlock",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "state_changing": True,
        "expected_guard": "require_root_admin_session",
        "public_justification": "",
    },
    "admin.staff_account_reactivate": {
        "endpoint": "admin.staff_account_reactivate",
        "rule": "/staff/<int:user_id>/reactivate",
        "methods": {"POST"},
        "access": "root_admin_session",
        "role": "root_admin",
        "classification": "staff_account",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "state_changing": True,
        "expected_guard": "require_root_admin_session",
        "public_justification": "",
    },
    "admin.staff_account_reset_activation": {
        "endpoint": "admin.staff_account_reset_activation",
        "rule": "/staff/<int:user_id>/reset-activation",
        "methods": {"POST"},
        "access": "root_admin_session",
        "role": "root_admin",
        "classification": "staff_account",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "state_changing": True,
        "expected_guard": "require_root_admin_session",
        "public_justification": "",
    },
    "admin.staff_account_resend_setup": {
        "endpoint": "admin.staff_account_resend_setup",
        "rule": "/staff/<int:user_id>/resend-setup",
        "methods": {"POST"},
        "access": "root_admin_session",
        "role": "root_admin",
        "classification": "staff_account",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "state_changing": True,
        "expected_guard": "require_root_admin_session",
        "public_justification": "",
    },
    "admin.admin_action_requests": {
        "endpoint": "admin.admin_action_requests",
        "rule": "/admin-action-requests",
        "methods": {"GET"},
        "access": "root_admin_session",
        "role": "root_admin",
        "classification": "admin_action_request",
        "csrf": "not_applicable",
        "rate_limit": "admin_session",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "require_root_admin_session",
        "public_justification": "",
    },
    "admin.admin_action_request_detail": {
        "endpoint": "admin.admin_action_request_detail",
        "rule": "/admin-action-requests/<int:request_id>",
        "methods": {"GET"},
        "access": "root_admin_session",
        "role": "root_admin",
        "classification": "admin_action_request",
        "csrf": "not_applicable",
        "rate_limit": "admin_session",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "require_root_admin_session",
        "public_justification": "",
    },
    "admin.admin_action_request_approve": {
        "endpoint": "admin.admin_action_request_approve",
        "rule": "/admin-action-requests/<int:request_id>/approve",
        "methods": {"POST"},
        "access": "root_admin_session",
        "role": "root_admin",
        "classification": "admin_action_request",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "state_changing": True,
        "expected_guard": "require_root_admin_session",
        "public_justification": "",
    },
    "admin.admin_action_request_reject": {
        "endpoint": "admin.admin_action_request_reject",
        "rule": "/admin-action-requests/<int:request_id>/reject",
        "methods": {"POST"},
        "access": "root_admin_session",
        "role": "root_admin",
        "classification": "admin_action_request",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "state_changing": True,
        "expected_guard": "require_root_admin_session",
        "public_justification": "",
    },
    "admin.admin_action_request_cancel": {
        "endpoint": "admin.admin_action_request_cancel",
        "rule": "/admin-action-requests/<int:request_id>/cancel",
        "methods": {"POST"},
        "access": "root_admin_session",
        "role": "root_admin",
        "classification": "admin_action_request",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "state_changing": True,
        "expected_guard": "require_root_admin_session",
        "public_justification": "",
    },
    "admin.disputes": {
        "endpoint": "admin.disputes",
        "rule": "/disputes",
        "methods": {"GET"},
        "access": "staff_session",
        "role": "staff",
        "classification": "transaction_dispute",
        "csrf": "not_applicable",
        "rate_limit": "admin_session",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "require_plain_staff_session",
        "public_justification": "",
    },
    "admin.dispute_detail": {
        "endpoint": "admin.dispute_detail",
        "rule": "/disputes/<int:dispute_id>",
        "methods": {"GET"},
        "access": "staff_session",
        "role": "staff",
        "classification": "transaction_dispute",
        "csrf": "not_applicable",
        "rate_limit": "admin_session",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "require_plain_staff_session",
        "public_justification": "",
    },
    "admin.dispute_transition": {
        "endpoint": "admin.dispute_transition",
        "rule": "/disputes/<int:dispute_id>/status",
        "methods": {"POST"},
        "access": "staff_session",
        "role": "staff",
        "classification": "transaction_dispute",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "state_changing": True,
        "expected_guard": "require_plain_staff_session",
        "public_justification": "",
    },
    "admin.support_tickets": {
        "endpoint": "admin.support_tickets",
        "rule": "/support-tickets",
        "methods": {"GET"},
        "access": "staff_session",
        "role": "staff",
        "classification": "support_ticket",
        "csrf": "not_applicable",
        "rate_limit": "admin_session",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "require_plain_staff_session",
        "public_justification": "",
    },
    "admin.support_ticket_detail": {
        "endpoint": "admin.support_ticket_detail",
        "rule": "/support-tickets/<int:ticket_id>",
        "methods": {"GET"},
        "access": "staff_session",
        "role": "staff",
        "classification": "support_ticket",
        "csrf": "not_applicable",
        "rate_limit": "admin_session",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "require_plain_staff_session",
        "public_justification": "",
    },
    "admin.support_ticket_transition": {
        "endpoint": "admin.support_ticket_transition",
        "rule": "/support-tickets/<int:ticket_id>/status",
        "methods": {"POST"},
        "access": "staff_session",
        "role": "staff",
        "classification": "support_ticket",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "state_changing": True,
        "expected_guard": "require_plain_staff_session",
        "public_justification": "",
    },
    "admin.audit_logs": {
        "endpoint": "admin.audit_logs",
        "rule": "/audit-logs",
        "methods": {"GET"},
        "access": "admin_session",
        "role": "admin",
        "classification": "audit",
        "csrf": "not_applicable",
        "rate_limit": "admin_session",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "require_admin_session",
        "public_justification": "",
    },
    "admin.audit_log_detail": {
        "endpoint": "admin.audit_log_detail",
        "rule": "/audit-logs/<int:event_id>",
        "methods": {"GET"},
        "access": "admin_session",
        "role": "admin",
        "classification": "audit",
        "csrf": "not_applicable",
        "rate_limit": "admin_session",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "require_admin_session",
        "public_justification": "",
    },
    "admin.alerts": {
        "endpoint": "admin.alerts",
        "rule": "/alerts",
        "methods": {"GET"},
        "access": "admin_session",
        "role": "admin",
        "classification": "alerts",
        "csrf": "not_applicable",
        "rate_limit": "admin_session",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "require_admin_session",
        "public_justification": "",
    },
    "admin.alert_delivery": {
        "endpoint": "admin.alert_delivery",
        "rule": "/alerts/deliver",
        "methods": {"POST"},
        "access": "admin_session",
        "role": "admin",
        "classification": "alerts",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "state_changing": True,
        "expected_guard": "require_admin_session",
        "public_justification": "",
    },
    "admin.manual_recovery_requests": {
        "endpoint": "admin.manual_recovery_requests",
        "rule": "/manual-recovery/requests",
        "methods": {"GET"},
        "access": "root_admin_session",
        "role": "root_admin",
        "classification": "manual_recovery",
        "csrf": "not_applicable",
        "rate_limit": "admin_session",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "require_root_admin_session",
        "public_justification": "",
    },
    "admin.manual_recovery_request_detail": {
        "endpoint": "admin.manual_recovery_request_detail",
        "rule": "/manual-recovery/requests/<int:request_id>",
        "methods": {"GET"},
        "access": "root_admin_session",
        "role": "root_admin",
        "classification": "manual_recovery",
        "csrf": "not_applicable",
        "rate_limit": "admin_session",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "require_root_admin_session",
        "public_justification": "",
    },
    "admin.manual_recovery_transition": {
        "endpoint": "admin.manual_recovery_transition",
        "rule": "/manual-recovery/requests/<int:request_id>/transition",
        "methods": {"POST"},
        "access": "root_admin_session",
        "role": "root_admin",
        "classification": "manual_recovery",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "state_changing": True,
        "expected_guard": "require_root_admin_session",
        "public_justification": "",
    },
    "admin.manual_recovery_complete": {
        "endpoint": "admin.manual_recovery_complete",
        "rule": "/manual-recovery/requests/<int:request_id>/complete",
        "methods": {"POST"},
        "access": "root_admin_session",
        "role": "root_admin",
        "classification": "manual_recovery",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "state_changing": True,
        "expected_guard": "require_root_admin_session",
        "public_justification": "",
    },
    "admin.invite_accept_info": {
        "endpoint": "admin.invite_accept_info",
        "rule": "/invites/accept/<token>",
        "methods": {"GET"},
        "access": "public_token",
        "role": "invite_token_holder",
        "classification": "staff_invite_acceptance",
        "csrf": "not_applicable",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "state_changing": False,
        "expected_guard": "invite_token_validation",
        "public_justification": "Invite acceptance lookup is reachable only with a high-entropy invite token.",
    },
    "admin.invite_accept_start": {
        "endpoint": "admin.invite_accept_start",
        "rule": "/invites/accept/<token>/start",
        "methods": {"POST"},
        "access": "public_token",
        "role": "invite_token_holder",
        "classification": "staff_invite_acceptance",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "state_changing": True,
        "expected_guard": "invite_token_validation",
        "public_justification": "Invite setup starts only after server-side invite-token validation.",
    },
    "admin.invite_accept_verify": {
        "endpoint": "admin.invite_accept_verify",
        "rule": "/invites/accept/<token>/verify",
        "methods": {"POST"},
        "access": "public_token",
        "role": "invite_token_holder",
        "classification": "staff_invite_acceptance",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "invite_totp_setup",
        "state_changing": True,
        "expected_guard": "invite_token_validation",
        "public_justification": "Invite verification validates the invite token, workplace OTP, and new staff TOTP code.",
    },
}


def _actual_routes(flask_app):
    routes = {}
    duplicates = {}
    for rule in flask_app.url_map.iter_rules():
        if rule.endpoint == "static":
            continue
        route = {
            "rule": rule.rule,
            "methods": set(rule.methods) - {"HEAD", "OPTIONS"},
        }
        if rule.endpoint in routes:
            duplicates.setdefault(rule.endpoint, [routes[rule.endpoint]]).append(route)
            continue
        routes[rule.endpoint] = route
    assert not duplicates, f"Admin route endpoints must be unique: {duplicates}"
    return routes


def _decorator_name(decorator: ast.expr) -> str:
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Name):
        return target.id
    return ast.dump(target)


def _route_source_inventory():
    text = ADMIN_ROUTE_MODULE.read_text(encoding="utf-8")
    lines = text.splitlines()
    tree = ast.parse(text)
    decorators = {}
    sources = {}
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        names = {_decorator_name(decorator) for decorator in node.decorator_list}
        if names.intersection({"route", "get", "post", "put", "patch", "delete"}):
            endpoint = f"admin.{node.name}"
            decorators[endpoint] = names
            sources[endpoint] = "\n".join(lines[node.lineno - 1 : node.end_lineno])
    return decorators, sources


def _admin_app():
    return create_app(TestConfig, app_mode="admin")


def _customer_app():
    return create_app(TestConfig, app_mode="customer")


def test_admin_route_inventory_matches_registered_flask_routes():
    actual = _actual_routes(_admin_app())
    expected = {
        endpoint: {
            "rule": entry["rule"],
            "methods": entry["methods"],
        }
        for endpoint, entry in ADMIN_ROUTE_SECURITY_INVENTORY.items()
    }

    assert actual == expected


def test_admin_route_inventory_has_complete_security_decisions():
    actual = _actual_routes(_admin_app())
    decorators, sources = _route_source_inventory()

    for endpoint, entry in ADMIN_ROUTE_SECURITY_INVENTORY.items():
        assert entry["endpoint"] == endpoint
        assert entry["rule"] == actual[endpoint]["rule"]
        assert entry["methods"] == actual[endpoint]["methods"]
        assert entry["access"] in ACCESS_DECISIONS
        assert entry["role"] in ROLE_DECISIONS
        assert entry["classification"]
        assert entry["csrf"] in CSRF_DECISIONS
        assert entry["rate_limit"] in RATE_LIMIT_DECISIONS
        assert entry["step_up"] in STEP_UP_DECISIONS
        assert isinstance(entry["state_changing"], bool)
        assert entry["expected_guard"] in GUARD_DECISIONS

        route_decorators = decorators[endpoint]
        source = sources[endpoint]

        if entry["methods"].intersection(UNSAFE_METHODS):
            assert entry["csrf"] == "required", f"{endpoint} must have an unsafe-method CSRF decision"
            assert "exempt" not in route_decorators, f"{endpoint} must not be CSRF-exempt"
        else:
            assert entry["csrf"] == "not_applicable"

        if entry["access"] in {"public", "public_token"}:
            assert entry["public_justification"], f"{endpoint} needs a public-route justification"
            assert "require_staff_session" not in source
            assert "require_root_admin_session" not in source
        else:
            assert not entry["public_justification"]

        if entry["rate_limit"] == "per_route":
            assert "limit" in route_decorators, f"{endpoint} is expected to have Flask-Limiter decorators"

        if entry["expected_guard"] == "require_staff_session":
            assert "require_staff_session" in source, f"{endpoint} must call require_staff_session"
        if entry["expected_guard"] == "require_plain_staff_session":
            assert "require_plain_staff_session" in source, f"{endpoint} must call require_plain_staff_session"
        if entry["expected_guard"] == "require_admin_session":
            assert "require_admin_session" in source, f"{endpoint} must call require_admin_session"
        if entry["expected_guard"] == "require_root_admin_session":
            assert "require_root_admin_session" in source, f"{endpoint} must call require_root_admin_session"
        if entry["expected_guard"] == "pending_admin_mfa_session":
            assert (
                "complete_admin_mfa_login" in source or "pending_mfa_user_id" in source
            ), f"{endpoint} must require pending admin MFA state"
        if entry["expected_guard"] == "invite_token_validation":
            assert "<token>" in entry["rule"]
            assert any(
                service_call in source
                for service_call in (
                    "invite_info",
                    "start_invite_acceptance",
                    "verify_invite_acceptance",
                )
            ), f"{endpoint} must delegate to invite-token validation"

        if entry["step_up"] == "required":
            assert (
                "totp_code" in source or "_ADMIN_TOTP_CODE_FIELD" in source
            ), f"{endpoint} must handle a TOTP step-up code"
        if entry["step_up"] == "invite_totp_setup":
            assert "totp_code" in source
            assert "workplace_verification_code" in source


def test_admin_and_customer_route_inventories_are_separate():
    admin_actual = _actual_routes(_admin_app())
    customer_actual = _actual_routes(_customer_app())

    assert all(endpoint.startswith("admin.") for endpoint in admin_actual)
    assert not any(endpoint.startswith("admin.") for endpoint in customer_actual)
    assert not any(rule["rule"].startswith("/manual-recovery") for rule in customer_actual.values())
    assert not any(
        endpoint.startswith(("auth.", "web.", "banking.", "main."))
        for endpoint in ADMIN_ROUTE_SECURITY_INVENTORY
    )
