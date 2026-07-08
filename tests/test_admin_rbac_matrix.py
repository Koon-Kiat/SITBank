from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.extensions import db
from app.models import AdminActionRequest, ManualRecoveryRequest, StaffInvite, User
from test_admin_route_inventory_security import ADMIN_ROUTE_SECURITY_INVENTORY


ROLE_ORDER = ("unauthenticated", "customer", "staff", "admin", "root_admin")

READ_PERMISSION_MATRIX = {
    "admin.index": {
        "rule": "/",
        "expected": (401, 401, 200, 200, 200),
    },
    "admin.disputes": {
        "rule": "/disputes",
        "expected": (401, 401, 200, 403, 403),
    },
    "admin.support_tickets": {
        "rule": "/support-tickets",
        "expected": (401, 401, 200, 403, 403),
    },
    "admin.audit_logs": {
        "rule": "/audit-logs",
        "expected": (401, 401, 403, 200, 200),
    },
    "admin.alerts": {
        "rule": "/alerts",
        "expected": (401, 401, 403, 200, 200),
    },
    "admin.staff_accounts": {
        "rule": "/staff",
        "expected": (401, 401, 403, 200, 200),
    },
    "admin.invites": {
        "rule": "/invites",
        "expected": (401, 401, 403, 403, 200),
    },
    "admin.manual_recovery_requests": {
        "rule": "/manual-recovery/requests",
        "expected": (401, 401, 403, 403, 200),
    },
    "admin.customer_security_locks": {
        "rule": "/customer-security-locks",
        "expected": (401, 401, 403, 403, 200),
    },
    "admin.admin_action_requests": {
        "rule": "/admin-action-requests",
        "expected": (401, 401, 403, 403, 200),
    },
}

FORBIDDEN_MUTATION_MATRIX = {
    "admin.invite_create": {
        "rule": "/invites",
        "roles": ("unauthenticated", "customer", "staff", "admin"),
        "payload": {
            "workplace_email": "matrix.staff@sit.singaporetech.edu.sg",
            "role": "staff",
            "totp_code": "000000",
        },
    },
    "admin.alert_delivery": {
        "rule": "/alerts/deliver",
        "roles": ("unauthenticated", "customer", "staff"),
        "payload": {"totp_code": "000000"},
    },
    "admin.staff_account_deactivate": {
        "rule": "/staff/999999/deactivate",
        "roles": ("unauthenticated", "customer", "staff", "admin"),
        "payload": {"totp_code": "000000"},
    },
    "admin.customer_security_unlock_request": {
        "rule": "/customers/999999/security-unlock-requests",
        "roles": ("unauthenticated", "customer", "staff", "admin"),
        "payload": {"totp_code": "000000"},
    },
    "admin.manual_recovery_transition": {
        "rule": "/manual-recovery/requests/999999/transition",
        "roles": ("unauthenticated", "customer", "staff", "admin"),
        "payload": {
            "status": "under_review",
            "reason": "fake matrix review",
            "totp_code": "000000",
        },
    },
}

# These endpoints have parameter/state contracts that are more usefully covered
# by the named focused suites. Keeping the list beside the matrix makes any new
# protected route an explicit review decision.
FOCUSED_RBAC_ENDPOINTS = {
    "admin.admin_action_request_approve",
    "admin.admin_action_request_cancel",
    "admin.admin_action_request_detail",
    "admin.admin_action_request_reject",
    "admin.audit_log_detail",
    "admin.customer_freeze",
    "admin.customer_freeze_lookup_form",
    "admin.customer_unfreeze",
    "admin.customer_unfreeze_requests",
    "admin.dispute_detail",
    "admin.dispute_transition",
    "admin.invite_reissue",
    "admin.invite_reset_acceptance",
    "admin.invite_revoke",
    "admin.manual_recovery_complete",
    "admin.manual_recovery_request_detail",
    "admin.mfa_change_confirm",
    "admin.mfa_change_form",
    "admin.mfa_change_start",
    "admin.password_change_form",
    "admin.password_change_submit",
    "admin.support_ticket_detail",
    "admin.support_ticket_transition",
    "admin.staff_account_reactivate",
    "admin.staff_account_resend_setup",
    "admin.staff_account_reset_activation",
}


@pytest.fixture()
def rbac_users():
    users = {}
    for index, role in enumerate(("customer", "staff", "admin", "root_admin"), start=1):
        email = (
            f"matrix-{role}@example.test"
            if role == "customer"
            else f"matrix-{role}@sit.singaporetech.edu.sg"
        )
        if role == "root_admin":
            email = "root1@sit.singaporetech.edu.sg"
        user = User(
            username=f"matrix-{role}",
            email=email,
            password_hash="clearly-fake-test-password-hash",
            account_type=role,
            account_status="active",
            full_name=f"Matrix {role}",
            phone_number=f"8{index:07d}",
            account_number=f"{index:012d}" if role == "customer" else None,
            workplace_email_verified_at=(
                None if role == "customer" else datetime.now(timezone.utc)
            ),
            mfa_enabled=True,
        )
        db.session.add(user)
        users[role] = user
    db.session.commit()
    return users


def _client_for_role(admin_app, users, role):
    client = admin_app.test_client()
    if role in {"unauthenticated", "customer"}:
        return client
    primary = client.post(
        "/login",
        json={
            "workplace_email": users[role].email,
            "password": "clearly-fake-test-password",
        },
    )
    assert primary.status_code == 200
    verified = client.post("/mfa/verify", json={"totp_code": "123456"})
    assert verified.status_code == 200
    return client


def _trust_test_totp(monkeypatch) -> None:
    # Admin login and step-up verify through both the boolean helper and the
    # replay-aware outcome helper, so trust both in RBAC matrix scaffolding.
    monkeypatch.setattr(
        "app.admin.services._verify_totp_for_user",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        "app.admin.services._verify_totp_for_user_outcome",
        lambda *_args, **_kwargs: "valid",
    )


def test_admin_read_permission_matrix(
    admin_app,
    rbac_users,
    monkeypatch,
):
    monkeypatch.setattr(
        "app.admin.services._admin_password_matches",
        lambda *_args, **_kwargs: True,
    )
    _trust_test_totp(monkeypatch)
    for role_index, role in enumerate(ROLE_ORDER):
        role_client = _client_for_role(admin_app, rbac_users, role)
        for endpoint, entry in READ_PERMISSION_MATRIX.items():
            response = role_client.get(
                entry["rule"],
                headers={"Accept": "application/json"},
            )
            assert response.status_code == entry["expected"][role_index], (
                role,
                endpoint,
                response.get_data(as_text=True),
            )


@pytest.mark.parametrize("endpoint", sorted(FORBIDDEN_MUTATION_MATRIX))
def test_forbidden_admin_mutations_have_no_privileged_side_effect(
    admin_app,
    rbac_users,
    endpoint,
    monkeypatch,
):
    delivery_calls = []
    monkeypatch.setattr(
        "app.admin.services._admin_password_matches",
        lambda *_args, **_kwargs: True,
    )
    _trust_test_totp(monkeypatch)
    monkeypatch.setattr(
        "app.admin.routes.deliver_security_alerts",
        lambda *_args, **_kwargs: delivery_calls.append(True),
        raising=False,
    )
    entry = FORBIDDEN_MUTATION_MATRIX[endpoint]
    before = {
        "invites": db.session.query(StaffInvite).count(),
        "requests": db.session.query(AdminActionRequest).count(),
        "recoveries": db.session.query(ManualRecoveryRequest).count(),
    }
    for role in entry["roles"]:
        response = _client_for_role(admin_app, rbac_users, role).post(
            entry["rule"],
            json=entry["payload"],
        )
        assert response.status_code in {401, 403}
    after = {
        "invites": db.session.query(StaffInvite).count(),
        "requests": db.session.query(AdminActionRequest).count(),
        "recoveries": db.session.query(ManualRecoveryRequest).count(),
    }
    assert after == before
    assert delivery_calls == []


def test_protected_admin_route_inventory_requires_matrix_or_focused_coverage():
    protected_endpoints = {
        endpoint
        for endpoint, entry in ADMIN_ROUTE_SECURITY_INVENTORY.items()
        if entry["access"]
        in {"staff_session", "admin_session", "root_admin_session"}
    }
    matrix_endpoints = set(READ_PERMISSION_MATRIX) | set(
        FORBIDDEN_MUTATION_MATRIX
    )
    assert protected_endpoints == matrix_endpoints | FOCUSED_RBAC_ENDPOINTS
