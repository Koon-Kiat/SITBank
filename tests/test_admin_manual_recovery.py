from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

import pyotp
import pytest

from app.admin.routes import (
    _manual_recovery_failure_message,
    _manual_recovery_transition_options,
)
from app.extensions import db
from app.models import AdminActionRequest, ManualRecoveryRequest, SecurityAuditEvent, User
from app.security.crypto import encrypt_mfa_secret
from app.security.email import password_reset_outbox
from app.security.passwords import hash_password
from app.auth.services import AuthError
from conftest import TestConfig


ROOT_EMAIL = "root1@sit.singaporetech.edu.sg"
ROOT_PASSWORD = "correct horse battery staple"


@pytest.fixture()
def admin_app(monkeypatch):
    from app import create_app
    from app.security import passwords

    monkeypatch.setattr(passwords, "_is_password_pwned_by_hibp", lambda _password: False)
    flask_app = create_app(TestConfig, app_mode="admin")
    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def admin_client(admin_app):
    return admin_app.test_client()


def _rules(flask_app):
    return {
        rule.rule: rule.endpoint
        for rule in flask_app.url_map.iter_rules()
        if rule.endpoint != "static"
    }


def _create_staff_identity(
    *,
    username: str,
    email: str,
    account_type: str,
    phone_number: str,
    password: str = ROOT_PASSWORD,
) -> tuple[User, str]:
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        account_type=account_type,
        account_status="active",
        full_name=username.replace("-", " ").title(),
        phone_number=phone_number,
        account_number=None,
        workplace_email_verified_at=datetime.now(timezone.utc),
    )
    db.session.add(user)
    db.session.flush()
    secret = pyotp.random_base32(length=32)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(secret, user.id)
    user.mfa_enabled = True
    db.session.commit()
    return user, secret


def _create_customer(username: str = "recover-admin01") -> tuple[User, str]:
    user = User(
        username=username,
        email=f"{username}@example.com",
        password_hash=hash_password("Correct-Horse-Battery-Staple-2026!"),
        account_type="customer",
        account_status="active",
        full_name="Recover Customer",
        phone_number=f"8{int(datetime.now(timezone.utc).timestamp()) % 10000000:07d}",
        account_number=f"123{int(datetime.now(timezone.utc).timestamp()) % 1000000000:09d}",
    )
    db.session.add(user)
    db.session.flush()
    secret = pyotp.random_base32(length=32)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(secret, user.id)
    user.mfa_enabled = True
    db.session.commit()
    return user, secret


def _create_manual_recovery_request(
    user: User | None,
    *,
    status: str = "pending",
    expired: bool = False,
) -> ManualRecoveryRequest:
    now = datetime.now(timezone.utc)
    request_record = ManualRecoveryRequest(
        identifier_ref=f"manual-request-ref-{user.id if user else 'unlinked'}",
        user_id=user.id if user else None,
        status=status,
        requested_ip="203.0.113.10",
        requested_user_agent="unit-test",
        request_count=1,
        created_at=now,
        updated_at=now,
        last_submitted_at=now,
        expires_at=now - timedelta(minutes=1) if expired else now + timedelta(days=7),
        status_changed_at=now,
    )
    db.session.add(request_record)
    db.session.commit()
    return request_record


def _login_admin(client, secret: str, email: str = ROOT_EMAIL, password: str = ROOT_PASSWORD):
    password_response = client.post(
        "/login",
        json={"workplace_email": email, "password": password},
    )
    assert password_response.status_code == 200
    verify_response = client.post(
        "/mfa/verify",
        json={"totp_code": _totp(secret)},
    )
    assert verify_response.status_code == 200
    return verify_response


def _totp(secret: str) -> str:
    return pyotp.TOTP(secret, digits=6, interval=30).now()


def _assert_no_sensitive_recovery_material(payload: dict) -> None:
    body = json.dumps(payload, sort_keys=True).casefold()
    forbidden = [
        "identifier_ref",
        "requested_ip",
        "requested_user_agent",
        "reset_token",
        "recovery_code",
        "mfa_secret",
        "mfa_secret_nonce",
        "mfa_secret_ciphertext",
        "password_hash",
        "session_id",
        "session_lookup",
        "hmac",
    ]
    for item in forbidden:
        assert item not in body


def _enable_browser_csrf_and_get_token(admin_app, admin_client, path: str) -> str:
    admin_app.config["WTF_CSRF_ENABLED"] = True
    response = admin_client.get(path)
    assert response.status_code == 200
    match = re.search(
        r'name="csrf_token"[^>]*value="([^"]+)"',
        response.get_data(as_text=True),
    )
    assert match is not None
    return match.group(1)


def test_manual_recovery_routes_are_admin_app_only():
    from app import create_app

    customer_app = create_app(TestConfig, app_mode="customer")
    admin_app = create_app(TestConfig, app_mode="admin")

    customer_rules = _rules(customer_app)
    admin_rules = _rules(admin_app)

    assert "/manual-recovery/requests" not in customer_rules
    assert not any(rule.startswith("/manual-recovery") for rule in customer_rules)
    assert admin_rules["/manual-recovery/requests"] == "admin.manual_recovery_requests"
    assert (
        admin_rules["/manual-recovery/requests/<int:request_id>"]
        == "admin.manual_recovery_request_detail"
    )
    assert (
        admin_rules["/manual-recovery/requests/<int:request_id>/transition"]
        == "admin.manual_recovery_transition"
    )
    assert (
        admin_rules["/manual-recovery/requests/<int:request_id>/complete"]
        == "admin.manual_recovery_complete"
    )


def test_manual_recovery_routes_require_authentication(admin_client):
    assert admin_client.get("/manual-recovery/requests").status_code == 401
    assert admin_client.post("/manual-recovery/requests/1/transition", json={}).status_code == 401
    assert admin_client.post("/manual-recovery/requests/1/complete", json={}).status_code == 401


def test_non_root_staff_cannot_review_or_mutate_manual_recovery(admin_client):
    _staff, staff_secret = _create_staff_identity(
        username="staff-admin",
        email="staff.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234567",
    )
    customer, _customer_secret = _create_customer("recover-staff-denied")
    request_record = _create_manual_recovery_request(customer)
    _login_admin(admin_client, staff_secret, email="staff.admin@sit.singaporetech.edu.sg")

    listed = admin_client.get("/manual-recovery/requests")
    transitioned = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/transition",
        json={"status": "under_review", "reason": "identity review", "totp_code": _totp(staff_secret)},
    )
    completed = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/complete",
        json={"reason": "identity verified", "totp_code": _totp(staff_secret)},
    )

    assert listed.status_code == 403
    assert transitioned.status_code == 403
    assert completed.status_code == 403


def test_root_admin_can_list_pending_manual_recovery_requests(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    customer, _customer_secret = _create_customer("recover-list")
    request_record = _create_manual_recovery_request(customer)
    _login_admin(admin_client, root_secret)

    response = admin_client.get(
        "/manual-recovery/requests",
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["requests"][0]["id"] == request_record.id
    assert payload["requests"][0]["status"] == "pending"
    assert payload["requests"][0]["linked_customer"] is True
    _assert_no_sensitive_recovery_material(payload)


def test_root_admin_gets_browser_manual_recovery_queue_by_default(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    customer, _customer_secret = _create_customer("recover-browser-list")
    request_record = _create_manual_recovery_request(customer)
    _login_admin(admin_client, root_secret)

    response = admin_client.get("/manual-recovery/requests")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert response.content_type.startswith("text/html")
    assert "Manual Recovery" in body
    assert "Queue Summary" in body
    assert f"/manual-recovery/requests/{request_record.id}" in body
    assert "Unlinked requests are intentionally generic" in body
    _assert_no_sensitive_recovery_material({"html": body})


def test_browser_manual_recovery_queue_filters_active_closed_and_linked_states(admin_client):
    root, root_secret = _create_staff_identity(
        username="root-browser-filter",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="89990012",
    )
    customer, _customer_secret = _create_customer("recover-filter01")
    active_request = _create_manual_recovery_request(customer, status="pending")
    approved_request = _create_manual_recovery_request(customer, status="approved")
    closed_unlinked_request = _create_manual_recovery_request(None, status="denied")
    _login_admin(admin_client, root_secret, root.email)

    linked = admin_client.get(
        "/manual-recovery/requests?status=pending&linked=linked&active=active&sort=status&direction=asc"
    )
    closed = admin_client.get(
        "/manual-recovery/requests?linked=unlinked&active=closed&sort=updated_at&direction=desc"
    )

    assert linked.status_code == 200
    linked_body = linked.get_data(as_text=True)
    assert f"#{active_request.id}" in linked_body
    assert f"#{approved_request.id}" not in linked_body
    assert f"#{closed_unlinked_request.id}" not in linked_body
    assert closed.status_code == 200
    closed_body = closed.get_data(as_text=True)
    assert f"#{closed_unlinked_request.id}" in closed_body
    assert "Unlinked or unknown" in closed_body
    assert "Closed" in closed_body


def test_browser_manual_recovery_missing_detail_returns_not_found(admin_client):
    root, root_secret = _create_staff_identity(
        username="root-browser-missing",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="89990013",
    )
    _login_admin(admin_client, root_secret, root.email)

    response = admin_client.get("/manual-recovery/requests/999")

    assert response.status_code == 404


def test_manual_recovery_detail_renders_safe_forms(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    customer, _customer_secret = _create_customer("recover-browser-detail")
    request_record = _create_manual_recovery_request(customer, status="under_review")
    _login_admin(admin_client, root_secret)

    response = admin_client.get(f"/manual-recovery/requests/{request_record.id}")
    body = response.get_data(as_text=True)
    json_response = admin_client.get(
        f"/manual-recovery/requests/{request_record.id}",
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 200
    assert f"Request #{request_record.id}" in body
    assert "manual-recovery-transition-status" in body
    assert 'name="csrf_token"' in body
    assert 'autocomplete="one-time-code"' in body
    assert 'maxlength="6"' in body
    assert "approved" in body
    assert "denied" in body
    assert json_response.status_code == 200
    assert json_response.get_json()["request"]["id"] == request_record.id
    _assert_no_sensitive_recovery_material({"html": body, "json": json_response.get_json()})


def test_manual_recovery_display_helpers_cover_safe_state_labels():
    assert _manual_recovery_transition_options({"status": "pending"}) == ["under_review", "denied"]
    assert _manual_recovery_transition_options({"status": "under_review"}) == ["approved", "denied"]
    assert _manual_recovery_transition_options({"status": "completed"}) == []
    assert (
        _manual_recovery_failure_message(AuthError("missing", 404))
        == "Manual recovery request was not found."
    )
    assert (
        _manual_recovery_failure_message(AuthError("forbidden", 403))
        == "Manual recovery action was not authorized."
    )
    assert (
        _manual_recovery_failure_message(AuthError("unexpected", 418))
        == "Manual recovery action could not be completed."
    )


def test_browser_transition_requires_valid_fields_and_redirects_safely(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    customer, _customer_secret = _create_customer("recover-browser-transition")
    request_record = _create_manual_recovery_request(customer)
    _login_admin(admin_client, root_secret)

    invalid = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/transition",
        data={"status": "under_review", "reason": "identity review"},
        follow_redirects=False,
    )
    db.session.refresh(request_record)
    assert invalid.status_code == 303
    assert invalid.headers["Location"].endswith(f"/manual-recovery/requests/{request_record.id}")
    assert request_record.status == "pending"

    valid = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/transition",
        data={
            "status": "under_review",
            "reason": "identity review started",
            "totp_code": _totp(root_secret),
        },
        follow_redirects=False,
    )

    assert valid.status_code == 303
    assert valid.headers["Location"].endswith(f"/manual-recovery/requests/{request_record.id}")
    db.session.refresh(request_record)
    assert request_record.status == "under_review"


@pytest.mark.parametrize("csrf_value", (None, "invalid-browser-csrf-token"))
def test_browser_transition_rejects_missing_or_invalid_csrf_before_mutation(
    admin_app,
    admin_client,
    csrf_value,
):
    root, root_secret = _create_staff_identity(
        username="root-browser-transition-csrf",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="89990020",
    )
    customer, _customer_secret = _create_customer("recover-csrf-transition")
    request_record = _create_manual_recovery_request(customer)
    _login_admin(admin_client, root_secret, root.email)
    _enable_browser_csrf_and_get_token(
        admin_app,
        admin_client,
        f"/manual-recovery/requests/{request_record.id}",
    )
    form = {
        "status": "under_review",
        "reason": "identity review started",
        "totp_code": _totp(root_secret),
    }
    if csrf_value is not None:
        form["csrf_token"] = csrf_value

    response = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/transition",
        data=form,
        follow_redirects=False,
    )

    assert response.status_code == 400
    db.session.refresh(request_record)
    assert request_record.status == "pending"


def test_browser_transition_accepts_valid_csrf_and_security_fields(
    admin_app,
    admin_client,
):
    root, root_secret = _create_staff_identity(
        username="root-browser-transition-valid-csrf",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="89990021",
    )
    customer, _customer_secret = _create_customer("recover-valid-csrf-transition")
    request_record = _create_manual_recovery_request(customer)
    _login_admin(admin_client, root_secret, root.email)
    csrf_token = _enable_browser_csrf_and_get_token(
        admin_app,
        admin_client,
        f"/manual-recovery/requests/{request_record.id}",
    )

    response = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/transition",
        data={
            "csrf_token": csrf_token,
            "status": "under_review",
            "reason": "identity review started",
            "totp_code": _totp(root_secret),
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    db.session.refresh(request_record)
    assert request_record.status == "under_review"


def test_browser_transition_auth_error_redirects_with_safe_flash(admin_client):
    root, root_secret = _create_staff_identity(
        username="root-browser-auth-error",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="89990014",
    )
    customer, _customer_secret = _create_customer("recover-browser-auth")
    request_record = _create_manual_recovery_request(customer)
    _login_admin(admin_client, root_secret, root.email)

    response = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/transition",
        data={
            "status": "under_review",
            "reason": "identity review started",
            "totp_code": "000000",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["Location"].endswith(f"/manual-recovery/requests/{request_record.id}")
    db.session.refresh(request_record)
    assert request_record.status == "pending"


def test_browser_completion_requires_approval_and_queues_maker_checker(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _second_root, second_root_secret = _create_staff_identity(
        username="root-admin-two",
        email="root2@sit.singaporetech.edu.sg",
        account_type="root_admin",
        phone_number="91234568",
    )
    customer, _customer_secret = _create_customer("recover-browser-complete")
    pending_request = _create_manual_recovery_request(customer)
    approved_request = _create_manual_recovery_request(customer, status="approved")
    _login_admin(admin_client, root_secret)

    blocked = admin_client.post(
        f"/manual-recovery/requests/{pending_request.id}/complete",
        data={"reason": "identity verified", "totp_code": _totp(root_secret)},
        follow_redirects=False,
    )
    admin_client.post("/logout", headers={"Accept": "application/json"})
    _login_admin(admin_client, second_root_secret, email="root2@sit.singaporetech.edu.sg")
    queued = admin_client.post(
        f"/manual-recovery/requests/{approved_request.id}/complete",
        data={"reason": "identity verified", "totp_code": _totp(second_root_secret)},
        follow_redirects=False,
    )

    assert blocked.status_code == 303
    assert queued.status_code == 303
    assert queued.headers["Location"].endswith(f"/manual-recovery/requests/{approved_request.id}")
    assert db.session.query(AdminActionRequest).filter_by(
        operation_type="manual_recovery_complete",
        status="pending",
    ).count() == 1


def test_browser_completion_validation_redirects_before_service_call(admin_client):
    root, root_secret = _create_staff_identity(
        username="root-browser-complete-invalid",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="89990015",
    )
    customer, _customer_secret = _create_customer("recover-complete-invalid")
    request_record = _create_manual_recovery_request(customer, status="approved")
    _login_admin(admin_client, root_secret, root.email)

    response = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/complete",
        data={"reason": ""},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["Location"].endswith(f"/manual-recovery/requests/{request_record.id}")
    db.session.refresh(request_record)
    assert request_record.status == "approved"


def test_browser_completion_rejects_missing_csrf_before_queueing_action(
    admin_app,
    admin_client,
):
    root, root_secret = _create_staff_identity(
        username="root-browser-complete-csrf",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="89990022",
    )
    customer, _customer_secret = _create_customer("recover-csrf-complete")
    request_record = _create_manual_recovery_request(customer, status="approved")
    _login_admin(admin_client, root_secret, root.email)
    _enable_browser_csrf_and_get_token(
        admin_app,
        admin_client,
        f"/manual-recovery/requests/{request_record.id}",
    )

    response = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/complete",
        data={
            "reason": "identity verified",
            "totp_code": _totp(root_secret),
        },
        follow_redirects=False,
    )

    assert response.status_code == 400
    db.session.refresh(request_record)
    assert request_record.status == "approved"
    assert db.session.query(AdminActionRequest).filter_by(
        operation_type="manual_recovery_complete",
    ).count() == 0


def test_browser_completion_accepts_valid_csrf_and_queues_maker_checker(
    admin_app,
    admin_client,
):
    root, root_secret = _create_staff_identity(
        username="root-browser-complete-valid-csrf",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="89990023",
    )
    customer, _customer_secret = _create_customer("recover-valid-csrf-complete")
    request_record = _create_manual_recovery_request(customer, status="approved")
    _login_admin(admin_client, root_secret, root.email)
    csrf_token = _enable_browser_csrf_and_get_token(
        admin_app,
        admin_client,
        f"/manual-recovery/requests/{request_record.id}",
    )

    response = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/complete",
        data={
            "csrf_token": csrf_token,
            "reason": "identity verified",
            "totp_code": _totp(root_secret),
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert db.session.query(AdminActionRequest).filter_by(
        operation_type="manual_recovery_complete",
        status="pending",
    ).count() == 1


def test_admin_browser_logout_redirects_and_json_logout_remains_compatible(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _second_root, second_root_secret = _create_staff_identity(
        username="root-admin-two",
        email="root2@sit.singaporetech.edu.sg",
        account_type="root_admin",
        phone_number="91234568",
    )
    _login_admin(admin_client, root_secret)

    browser_logout = admin_client.post("/logout", follow_redirects=False)
    _login_admin(admin_client, second_root_secret, email="root2@sit.singaporetech.edu.sg")
    json_logout = admin_client.post("/logout", headers={"Accept": "application/json"})

    assert browser_logout.status_code == 303
    assert browser_logout.headers["Location"].endswith("/login")
    assert json_logout.status_code == 200
    assert json_logout.get_json() == {"message": "Logged out"}


def test_root_admin_transition_requires_totp_and_preserves_status(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    customer, _customer_secret = _create_customer("recover-transition-denied")
    request_record = _create_manual_recovery_request(customer)
    _login_admin(admin_client, root_secret)

    missing_totp = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/transition",
        json={"status": "under_review", "reason": "identity review"},
    )
    invalid_totp = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/transition",
        json={"status": "under_review", "reason": "identity review", "totp_code": "000000"},
    )

    db.session.refresh(request_record)
    assert missing_totp.status_code == 400
    assert invalid_totp.status_code == 403
    assert request_record.status == "pending"


def test_root_admin_cannot_transition_own_customer_manual_recovery(admin_client):
    root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    customer, _customer_secret = _create_customer("recover-self-root")
    root.staff_personal_email = customer.email
    request_record = _create_manual_recovery_request(customer)
    db.session.commit()
    _login_admin(admin_client, root_secret)

    response = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/transition",
        json={"status": "under_review", "reason": "identity review", "totp_code": _totp(root_secret)},
    )
    db.session.refresh(request_record)
    event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="staff_self_customer_action_blocked",
        outcome="blocked",
    ).one()

    assert response.status_code == 403
    assert request_record.status == "pending"
    assert event.user_id == root.id
    assert event.event_metadata["action_type"] == "manual_recovery_transition"


def test_root_admin_can_transition_manual_recovery_to_review_and_approval(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    customer, _customer_secret = _create_customer("recover-transition")
    request_record = _create_manual_recovery_request(customer)
    _login_admin(admin_client, root_secret)

    under_review = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/transition",
        json={
            "status": "under_review",
            "reason": "identity review started",
            "totp_code": _totp(root_secret),
        },
    )
    approved = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/transition",
        json={
            "status": "approved",
            "reason": "identity verified",
            "totp_code": _totp(root_secret),
        },
    )

    assert under_review.status_code == 200
    assert under_review.get_json()["request"]["status"] == "under_review"
    assert approved.status_code == 200
    approved_payload = approved.get_json()
    assert approved_payload["message"] == "Admin action approval required"
    assert approved_payload["request"]["operation_type"] == "manual_recovery_approve"
    assert approved_payload["request"]["status"] == "pending"
    db.session.refresh(request_record)
    assert request_record.status == "under_review"
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="manual_recovery_admin_transition",
        outcome="success",
    ).count() == 1
    assert db.session.query(AdminActionRequest).filter_by(
        operation_type="manual_recovery_approve",
        status="pending",
    ).count() == 1


def test_root_admin_cannot_complete_manual_recovery_before_approval(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    customer, _customer_secret = _create_customer("recover-complete-denied")
    request_record = _create_manual_recovery_request(customer)
    _login_admin(admin_client, root_secret)

    response = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/complete",
        json={"reason": "identity verified", "totp_code": _totp(root_secret)},
    )

    assert response.status_code == 409
    db.session.refresh(request_record)
    assert request_record.status == "pending"


def test_root_admin_can_complete_approved_manual_recovery(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    customer, _customer_secret = _create_customer("recover-complete")
    request_record = _create_manual_recovery_request(customer, status="approved")
    _login_admin(admin_client, root_secret)

    response = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/complete",
        json={"reason": "identity verified", "totp_code": _totp(root_secret)},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["message"] == "Admin action approval required"
    assert payload["request"]["operation_type"] == "manual_recovery_complete"
    assert payload["request"]["status"] == "pending"
    _assert_no_sensitive_recovery_material(payload)
    db.session.refresh(customer)
    db.session.refresh(request_record)
    assert customer.mfa_enabled is True
    assert request_record.completed_at is None
    assert "SITBank manual recovery completed" not in [
        item["subject"] for item in password_reset_outbox()
    ]
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="manual_recovery_completed",
        outcome="success",
    ).count() == 0
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="manual_recovery_admin_complete",
        outcome="success",
    ).count() == 0


def test_expired_manual_recovery_request_is_safely_rejected(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    customer, _customer_secret = _create_customer("recover-expired")
    request_record = _create_manual_recovery_request(customer, expired=True)
    _login_admin(admin_client, root_secret)

    response = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/transition",
        json={
            "status": "under_review",
            "reason": "identity review",
            "totp_code": _totp(root_secret),
        },
    )

    assert response.status_code == 409
    db.session.refresh(request_record)
    assert request_record.status == "expired"
