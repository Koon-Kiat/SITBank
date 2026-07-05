from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import pyotp
import pytest

from app.extensions import db
from app.models import (
    AdminActionRequest,
    AuthAttemptCounter,
    SecurityAuditEvent,
    StaffInvite,
    User,
)
from app.security.crypto import encrypt_mfa_secret
from app.security.passwords import hash_password


ROOT_EMAIL = "root1@sit.singaporetech.edu.sg"
ROOT_PASSWORD = "correct horse battery staple"
_FIXED_TOTP_TIME = int(time.time())


@pytest.fixture(autouse=True)
def freeze_totp_verifier_time(monkeypatch):
    global _FIXED_TOTP_TIME
    _FIXED_TOTP_TIME = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: _FIXED_TOTP_TIME)


def _create_staff_identity(
    *,
    username: str,
    email: str,
    account_type: str,
    phone_number: str,
    active: bool = True,
) -> tuple[User, str]:
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(ROOT_PASSWORD),
        account_type=account_type,
        account_status="active" if active else "setup_pending",
        full_name=username.replace("-", " ").title(),
        phone_number=phone_number,
        account_number=None,
        workplace_email_verified_at=datetime.now(timezone.utc) if active else None,
    )
    db.session.add(user)
    db.session.flush()
    secret = pyotp.random_base32(length=32)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(secret, user.id)
    user.mfa_enabled = active
    db.session.commit()
    return user, secret


def _login_admin(client, secret: str, email: str = ROOT_EMAIL, *, remote_addr: str | None = None):
    request_kwargs = {"environ_overrides": {"REMOTE_ADDR": remote_addr}} if remote_addr else {}
    password_response = client.post(
        "/login",
        json={"workplace_email": email, "password": ROOT_PASSWORD},
        **request_kwargs,
    )
    assert password_response.status_code == 200
    verify_response = client.post(
        "/mfa/verify",
        json={"totp_code": _totp(secret)},
        **request_kwargs,
    )
    assert verify_response.status_code == 200
    return verify_response


def _totp(secret: str) -> str:
    return pyotp.TOTP(secret, digits=6, interval=30).at(_FIXED_TOTP_TIME)


def _delivery_report(
    *,
    alert_count: int = 1,
    deliverable_alert_count: int = 1,
    alerts: list[dict] | None = None,
    delivery: dict | None = None,
    dedupe: dict | None = None,
) -> dict:
    return {
        "message": "security_alert_report",
        "generated_at": "2026-06-30T08:15:00+00:00",
        "alert_count": alert_count,
        "deliverable_alert_count": deliverable_alert_count,
        "alerts": alerts
        if alerts is not None
        else [
            {
                "alert_type": "manual_recovery_burst",
                "severity": "high",
                "count": 1,
                "window_seconds": 600,
                "source": "principal_ref:safe",
                "generated_at": "2026-06-30T08:15:00+00:00",
            }
        ],
        "audit_chain": {"checked": True, "valid": True, "anchor_configured": True},
        "database_integrity": {"checked": True, "configured": True, "valid": True},
        "dedupe": dedupe or {"enabled": True, "ttl_seconds": 300, "suppressed": 0},
        "delivery": delivery
        or {
            "attempted": True,
            "configured": True,
            "enabled": True,
            "delivered": True,
            "provider": "generic",
            "status_code": 204,
        },
    }


def test_admin_browser_login_and_mfa_reaches_dashboard(admin_app, admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )

    login_page = admin_client.get("/login")
    primary = admin_client.post(
        "/login",
        data={"workplace_email": ROOT_EMAIL, "password": ROOT_PASSWORD},
        follow_redirects=False,
    )

    with admin_client.session_transaction() as sess:
        pending_user_id = sess.get("pending_mfa_user_id")

    mfa_page = admin_client.get("/mfa/verify")
    verify = admin_client.post(
        "/mfa/verify",
        data={"totp_code": _totp(root_secret)},
        follow_redirects=False,
    )
    dashboard = admin_client.get("/")
    verify_cookies = verify.headers.getlist("Set-Cookie")

    assert login_page.status_code == 200
    login_body = login_page.get_data(as_text=True)
    assert 'action="/login"' in login_body
    assert 'name="workplace_email"' in login_body
    assert 'name="password"' in login_body
    assert primary.status_code == 303
    assert primary.headers["Location"].endswith("/mfa/verify")
    assert pending_user_id is not None
    assert mfa_page.status_code == 200
    assert 'name="totp_code"' in mfa_page.get_data(as_text=True)
    assert verify.status_code == 303
    assert verify.headers["Location"].endswith("/")
    assert any(
        cookie.startswith(f"{admin_app.config['SESSION_COOKIE_NAME']}=")
        and not cookie.startswith(f"{admin_app.config['SESSION_COOKIE_NAME']}=;")
        for cookie in verify_cookies
    )
    assert not any(cookie.startswith("__Host-sitbank_session=") for cookie in verify_cookies)
    assert dashboard.status_code == 200
    assert ROOT_EMAIL in dashboard.get_data(as_text=True)


def test_admin_browser_login_pages_redirect_authenticated_admin(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, root_secret)

    login_page = admin_client.get("/login", follow_redirects=False)
    mfa_page = admin_client.get("/mfa/verify", follow_redirects=False)

    assert login_page.status_code == 302
    assert login_page.headers["Location"].endswith("/")
    assert mfa_page.status_code == 302
    assert mfa_page.headers["Location"].endswith("/")


def test_admin_login_form_renders_session_expired_message(admin_client):
    response = admin_client.get("/login?session_expired=1")

    assert response.status_code == 200
    assert "Your admin session expired. Please log in again." in response.get_data(as_text=True)


def test_admin_browser_login_rejects_invalid_form_and_schema(monkeypatch, admin_client):
    invalid_form = admin_client.post("/login", data={})

    def reject_schema(_self, _payload):
        from marshmallow import ValidationError

        raise ValidationError("forced schema rejection")

    monkeypatch.setattr("app.admin.routes.AdminLoginSchema.load", reject_schema)
    schema_rejected = admin_client.post(
        "/login",
        data={"workplace_email": ROOT_EMAIL, "password": ROOT_PASSWORD},
    )

    assert invalid_form.status_code == 400
    assert "This field is required" in invalid_form.get_data(as_text=True)
    assert schema_rejected.status_code == 400
    assert "Invalid request" in schema_rejected.get_data(as_text=True)


def test_admin_json_login_contract_remains_compatible(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )

    primary = admin_client.post(
        "/login",
        json={"workplace_email": ROOT_EMAIL, "password": ROOT_PASSWORD},
    )
    verify = admin_client.post(
        "/mfa/verify",
        json={"totp_code": _totp(root_secret)},
    )

    assert primary.status_code == 200
    assert primary.get_json() == {"message": "MFA verification required", "mfa_required": True}
    assert verify.status_code == 200
    verify_payload = verify.get_json()
    assert verify_payload["message"] == "Login successful"
    assert verify_payload["session_ref"]
    assert verify_payload["user"]["email"] == ROOT_EMAIL


def test_admin_mfa_form_requires_pending_browser_challenge(admin_client):
    browser_response = admin_client.get("/mfa/verify", follow_redirects=False)
    json_response = admin_client.get("/mfa/verify", headers={"Accept": "application/json"})

    assert browser_response.status_code == 303
    assert browser_response.headers["Location"].endswith("/login")
    assert json_response.status_code == 401
    assert json_response.get_json() == {"error": "No pending MFA challenge"}


def test_admin_browser_mfa_post_requires_pending_challenge(admin_client):
    response = admin_client.post(
        "/mfa/verify",
        data={"totp_code": "123456"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["Location"].endswith("/login")


def test_admin_browser_mfa_rejects_invalid_form_and_bad_code(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    primary = admin_client.post(
        "/login",
        data={"workplace_email": ROOT_EMAIL, "password": ROOT_PASSWORD},
    )

    invalid_form = admin_client.post("/mfa/verify", data={"totp_code": "abc"})
    bad_code = "000000"
    if bad_code == _totp(root_secret):
        bad_code = "111111"
    bad_mfa = admin_client.post("/mfa/verify", data={"totp_code": bad_code})

    assert primary.status_code == 303
    assert invalid_form.status_code == 400
    assert "MFA code must be exactly 6 digits" in invalid_form.get_data(as_text=True)
    assert bad_mfa.status_code == 401
    assert "Invalid workplace email, password, or authentication code" in bad_mfa.get_data(as_text=True)


def test_admin_mfa_counts_only_wrong_codes_and_clears_on_fresh_primary_login(
    admin_client,
):
    global _FIXED_TOTP_TIME
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    valid_code = _totp(root_secret)
    invalid_code = "000000" if valid_code != "000000" else "111111"

    primary = admin_client.post(
        "/login",
        json={"workplace_email": ROOT_EMAIL, "password": ROOT_PASSWORD},
    )
    assert primary.status_code == 200
    for _attempt in range(5):
        response = admin_client.post(
            "/mfa/verify",
            json={"totp_code": invalid_code},
        )
        assert response.status_code == 401

    valid_after_threshold = admin_client.post(
        "/mfa/verify",
        json={"totp_code": valid_code},
    )
    assert valid_after_threshold.status_code == 200
    assert (
        db.session.query(AuthAttemptCounter)
        .filter_by(scope="admin_mfa_login")
        .count()
        == 0
    )

    admin_client.post("/logout")
    _FIXED_TOTP_TIME += 30
    valid_code = _totp(root_secret)
    invalid_code = "000000" if valid_code != "000000" else "111111"
    admin_client.post(
        "/login",
        json={"workplace_email": ROOT_EMAIL, "password": ROOT_PASSWORD},
    )
    for _attempt in range(5):
        response = admin_client.post(
            "/mfa/verify",
            json={"totp_code": invalid_code},
        )
        assert response.status_code == 401
    blocked = admin_client.post(
        "/mfa/verify",
        json={"totp_code": invalid_code},
    )
    assert blocked.status_code == 429
    assert blocked.headers["Retry-After"].isdigit()
    assert "totp_code" not in blocked.get_data(as_text=True)

    fresh_primary = admin_client.post(
        "/login",
        json={"workplace_email": ROOT_EMAIL, "password": ROOT_PASSWORD},
    )
    assert fresh_primary.status_code == 200
    recovered = admin_client.post(
        "/mfa/verify",
        json={"totp_code": valid_code},
    )
    assert recovered.status_code == 200


def test_admin_browser_form_payload_strips_csrf_token_for_invites(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, root_secret)

    response = admin_client.post(
        "/invites",
        data={
            "workplace_email": "staff.person@sit.singaporetech.edu.sg",
            "role": "staff",
            "totp_code": _totp(root_secret),
            "csrf_token": "browser-form-token",
        },
        follow_redirects=False,
    )
    invite = db.session.execute(db.select(StaffInvite)).scalar_one()

    assert response.status_code == 303
    assert response.headers["Location"].endswith("/invites")
    assert invite.workplace_email_normalized == "staff.person@sit.singaporetech.edu.sg"


def test_admin_browser_login_rejects_customer_accounts_with_generic_error(admin_client):
    db.session.add(
        User(
            username="customer-admin-try",
            email="customer.admin@sit.singaporetech.edu.sg",
            password_hash=hash_password(ROOT_PASSWORD),
            account_type="customer",
            account_status="active",
            full_name="Customer Admin Try",
            phone_number="91234567",
            account_number="100000001000",
            mfa_enabled=True,
        )
    )
    db.session.commit()

    response = admin_client.post(
        "/login",
        data={
            "workplace_email": "customer.admin@sit.singaporetech.edu.sg",
            "password": ROOT_PASSWORD,
        },
    )

    with admin_client.session_transaction() as sess:
        pending_user_id = sess.get("pending_mfa_user_id")
        authenticated_user_id = sess.get("user_id")

    body = response.get_data(as_text=True)
    assert response.status_code == 401
    assert "Invalid workplace email, password, or authentication code" in body
    assert pending_user_id is None
    assert authenticated_user_id is None


def test_admin_browser_login_rejects_staff_outside_admin_email_domains(admin_client):
    _staff, _secret = _create_staff_identity(
        username="external-staff",
        email="external.staff@example.com",
        account_type="staff",
        phone_number="91234567",
    )

    response = admin_client.post(
        "/login",
        data={
            "workplace_email": "external.staff@example.com",
            "password": ROOT_PASSWORD,
        },
    )

    with admin_client.session_transaction() as sess:
        pending_user_id = sess.get("pending_mfa_user_id")
        authenticated_user_id = sess.get("user_id")

    body = response.get_data(as_text=True)
    assert response.status_code == 401
    assert "Invalid workplace email, password, or authentication code" in body
    assert pending_user_id is None
    assert authenticated_user_id is None


def test_dashboard_renders_role_navigation_and_audits_access(admin_client):
    _staff, staff_secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        account_type="staff",
        phone_number="91234567",
    )
    _login_admin(admin_client, staff_secret, email="bank.staff@sit.singaporetech.edu.sg")

    staff_dashboard = admin_client.get("/")
    staff_audit = admin_client.get("/audit-logs")
    staff_accounts = admin_client.get("/staff")
    staff_alerts = admin_client.get("/alerts")
    staff_invites = admin_client.get("/invites")

    assert staff_dashboard.status_code == 200
    staff_body = staff_dashboard.get_data(as_text=True)
    assert "Business operations" in staff_body
    assert "Staff invites" not in staff_body
    assert "Manual recovery" not in staff_body
    assert [staff_audit.status_code, staff_accounts.status_code, staff_alerts.status_code, staff_invites.status_code] == [
        403,
        403,
        403,
        403,
    ]

    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="admin_dashboard_access",
        outcome="success",
    ).count() == 1


def test_admin_and_root_dashboards_show_only_authorized_operations(admin_client):
    _admin, admin_secret = _create_staff_identity(
        username="security-admin",
        email="security.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, admin_secret, email="security.admin@sit.singaporetech.edu.sg")
    admin_body = admin_client.get("/").get_data(as_text=True)

    assert "Audit logs" in admin_body
    assert "Alerts" in admin_body
    assert "Staff/admin users" in admin_body
    assert "Staff invites" not in admin_body
    assert "Manual recovery" not in admin_body

    admin_client.post("/logout")
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234568",
    )
    _login_admin(admin_client, root_secret)
    root_body = admin_client.get("/").get_data(as_text=True)

    assert "Staff invites" in root_body
    assert "Manual recovery" in root_body


def test_root_manages_staff_lifecycle_with_totp_and_safe_audit(admin_client):
    root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    target, _target_secret = _create_staff_identity(
        username="target-admin",
        email="target.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234568",
    )
    _login_admin(admin_client, root_secret)

    page = admin_client.get("/staff")
    missing_totp = admin_client.post(f"/staff/{target.id}/deactivate", json={})
    self_action = admin_client.post(
        f"/staff/{root.id}/deactivate",
        json={"totp_code": _totp(root_secret)},
    )
    deactivate = admin_client.post(
        f"/staff/{target.id}/deactivate",
        json={"totp_code": _totp(root_secret)},
    )
    reset = admin_client.post(
        f"/staff/{target.id}/reset-activation",
        json={"totp_code": _totp(root_secret)},
    )

    db.session.refresh(target)
    payload = page.get_data(as_text=True).casefold()
    assert page.status_code == 200
    assert "target.admin@sit.singaporetech.edu.sg" in payload
    assert "password_hash" not in payload
    assert "mfa_secret" not in payload
    assert missing_totp.status_code == 400
    assert self_action.status_code == 403
    assert deactivate.status_code == 200
    assert reset.status_code == 200
    assert deactivate.get_json()["message"] == "Admin action approval required"
    assert reset.get_json()["message"] == "Admin action approval required"
    assert target.account_status == "active"
    assert target.mfa_enabled is True
    assert target.mfa_secret_nonce is not None
    assert target.mfa_secret_ciphertext is not None
    assert db.session.query(AdminActionRequest).filter_by(
        operation_type="staff_deactivate",
        status="pending",
    ).count() == 1
    assert db.session.query(AdminActionRequest).filter_by(
        operation_type="staff_reset_activation",
        status="pending",
    ).count() == 1
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="staff_account_deactivated",
        outcome="success",
    ).count() == 0
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="staff_activation_reset",
        outcome="success",
    ).count() == 0


def test_non_root_admin_cannot_mutate_staff_lifecycle(admin_client):
    _admin, admin_secret = _create_staff_identity(
        username="security-admin",
        email="security.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234567",
    )
    target, _target_secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        account_type="staff",
        phone_number="91234568",
    )
    _login_admin(admin_client, admin_secret, email="security.admin@sit.singaporetech.edu.sg")

    response = admin_client.post(
        f"/staff/{target.id}/deactivate",
        json={"totp_code": _totp(admin_secret)},
    )

    db.session.refresh(target)
    assert response.status_code == 403
    assert target.account_status == "active"


def test_audit_viewer_filters_bounds_and_redacts_detail_metadata(admin_client):
    _admin, admin_secret = _create_staff_identity(
        username="security-admin",
        email="security.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234567",
    )
    db.session.add(
        SecurityAuditEvent(
            event_type="staff_invite_created",
            outcome="success",
            user_id=None,
            ip_address="203.0.113.10",
            user_agent="unit-test",
            correlation_id="audit-test-request",
            session_ref="safe-session-ref",
            event_metadata={
                "severity": "high",
                "target_role": "staff",
                "invite_token": "plaintext-token-should-not-render",
                "workplace_email_ref": "safe-ref",
            },
            created_at=datetime.now(timezone.utc),
        )
    )
    db.session.commit()
    event = db.session.query(SecurityAuditEvent).filter_by(event_type="staff_invite_created").one()
    _login_admin(admin_client, admin_secret, email="security.admin@sit.singaporetech.edu.sg")

    listing = admin_client.get(
        "/audit-logs?event_type=staff_invite_created&sort=event_type&direction=asc&per_page=2&page=1",
        headers={"Accept": "application/json"},
    )
    bounded = admin_client.get(
        "/audit-logs?sort=drop%20table&page=-7&per_page=500",
        headers={"Accept": "application/json"},
    )
    detail = admin_client.get(f"/audit-logs/{event.id}")

    assert listing.status_code == 200
    assert listing.get_json()["events"][0]["event_type"] == "staff_invite_created"
    assert bounded.status_code == 200
    assert bounded.get_json()["sort"] == "timestamp"
    assert bounded.get_json()["page"] == 1
    assert bounded.get_json()["per_page"] == 100
    detail_text = detail.get_data(as_text=True)
    assert detail.status_code == 200
    assert "workplace_email_ref" in detail_text
    assert "plaintext-token-should-not-render" not in detail_text
    assert "invite_token" not in detail_text
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="audit_log_view",
        outcome="success",
    ).count() == 2


def test_alert_review_is_admin_only_and_does_not_send_alerts(admin_client, monkeypatch):
    remote_addr = "203.0.113.41"
    _staff, staff_secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        account_type="staff",
        phone_number="91234567",
    )
    _login_admin(
        admin_client,
        staff_secret,
        email="bank.staff@sit.singaporetech.edu.sg",
        remote_addr=remote_addr,
    )
    assert admin_client.get("/alerts", environ_overrides={"REMOTE_ADDR": remote_addr}).status_code == 403
    assert admin_client.post(
        "/alerts/deliver",
        json={"totp_code": "123456"},
        environ_overrides={"REMOTE_ADDR": remote_addr},
    ).status_code == 403

    admin_client.post("/logout")
    _admin, admin_secret = _create_staff_identity(
        username="security-admin",
        email="security.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234568",
    )
    calls = []

    def fail_delivery(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("dashboard alert review must not deliver alerts")

    monkeypatch.setattr("app.security.alerts.deliver_security_alerts", fail_delivery)
    _login_admin(admin_client, admin_secret, email="security.admin@sit.singaporetech.edu.sg")
    response = admin_client.get("/alerts")

    assert response.status_code == 200
    assert "Security Alerts" in response.get_data(as_text=True)
    assert calls == []
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="security_alert_review",
        outcome="success",
    ).count() == 1


def test_alert_review_renders_actionable_safe_detail_without_raw_logs(admin_client, monkeypatch):
    _admin, admin_secret = _create_staff_identity(
        username="security-admin",
        email="security.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234568",
    )
    event = SecurityAuditEvent(
        event_type="manual_recovery_requested",
        outcome="requested",
        user_id=None,
        ip_address="203.0.113.50",
        user_agent="unit-test",
        correlation_id="alert-request-1",
        session_ref="safe-session-ref",
        event_metadata={"severity": "high", "request_ref": "safe-request-ref"},
        created_at=datetime.now(timezone.utc),
    )
    db.session.add(event)
    db.session.commit()
    sensitive_header = "Bearer " + "redacted-example"

    def fake_report(*, deliver):
        assert deliver is False
        return {
            "message": "security_alert_report",
            "generated_at": "2026-06-30T08:15:00+00:00",
            "alert_count": 1,
            "deliverable_alert_count": 1,
            "alerts": [
                {
                    "alert_type": "manual_recovery_burst",
                    "severity": "high",
                    "count": 3,
                    "window_seconds": 600,
                    "source": "principal_ref:safe",
                    "generated_at": "2026-06-30T08:15:00+00:00",
                    "latest_event_id": event.id,
                    "reason": sensitive_header,
                    "authorization": sensitive_header,
                }
            ],
            "audit_chain": {
                "checked": True,
                "valid": True,
                "anchor_configured": True,
                "event_count": 1,
                "latest_event_id": event.id,
            },
            "database_integrity": {
                "checked": True,
                "configured": True,
                "valid": True,
            },
            "dedupe": {"enabled": False, "ttl_seconds": 600, "suppressed": 0},
            "delivery": {"attempted": False, "configured": True, "enabled": True},
        }

    monkeypatch.setattr("app.admin.routes.build_security_alert_report", fake_report)
    _login_admin(admin_client, admin_secret, email="security.admin@sit.singaporetech.edu.sg")

    response = admin_client.get("/alerts?alert=alert-1")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Highest severity" in body
    assert "Database integrity" in body
    assert "Dedupe" in body
    assert "Next action" in body
    assert "Alert Detail" in body
    assert "manual_recovery_burst" in body
    assert f"/audit-logs/{event.id}" in body
    assert "[redacted]" in body
    assert sensitive_header not in body
    assert "authorization:" not in body.casefold()
    assert "review page is read-only" in body


def test_alert_review_next_actions_cover_integrity_and_generic_alerts(admin_client, monkeypatch):
    _admin, admin_secret = _create_staff_identity(
        username="security-admin",
        email="security.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234568",
    )
    reports = {
        "empty": {
            "generated_at": "2026-06-30T08:15:00+00:00",
            "alert_count": 0,
            "alerts": [],
            "audit_chain": {"checked": True, "valid": True},
            "database_integrity": {"checked": True, "valid": True},
            "dedupe": {"enabled": True, "suppressed": 0},
            "delivery": {"enabled": True},
        },
        "audit": {
            "generated_at": "2026-06-30T08:16:00+00:00",
            "alert_count": 1,
            "alerts": [
                {
                    "alert_type": "audit_chain_verification_failed",
                    "severity": "critical",
                    "source": "audit_chain",
                    "count": 1,
                    "window_seconds": 60,
                }
            ],
            "audit_chain": {"checked": True, "valid": False},
            "database_integrity": {"checked": True, "valid": True},
            "dedupe": {"enabled": True, "suppressed": 0},
            "delivery": {"enabled": True},
        },
        "database": {
            "generated_at": "2026-06-30T08:17:00+00:00",
            "alert_count": 2,
            "alerts": [
                {
                    "alert_type": "database_integrity_regression",
                    "severity": "high",
                    "source": "database_integrity",
                    "count": 2,
                    "window_seconds": 120,
                },
                {
                    "alert_type": "login_failure_burst",
                    "severity": "medium",
                    "source": "principal_ref:safe",
                    "count": 5,
                    "window_seconds": 300,
                },
            ],
            "audit_chain": {"checked": True, "valid": True},
            "database_integrity": {"checked": True, "valid": False},
            "dedupe": {"enabled": False, "suppressed": 0},
            "delivery": {"enabled": True},
        },
        "generic": {
            "generated_at": "2026-06-30T08:18:00+00:00",
            "alert_count": 1,
            "alerts": [
                {
                    "alert_type": "manual_security_alert",
                    "severity": "low",
                    "source": "",
                    "count": 1,
                    "window_seconds": 0,
                }
            ],
            "audit_chain": {"checked": True, "valid": True},
            "database_integrity": {"checked": True, "valid": True},
            "dedupe": {"enabled": False, "suppressed": 0},
            "delivery": {"enabled": False},
        },
    }
    selected = {"name": "empty"}

    def fake_report(*, deliver):
        assert deliver is False
        return reports[selected["name"]]

    monkeypatch.setattr("app.admin.routes.build_security_alert_report", fake_report)
    _login_admin(admin_client, admin_secret, email="security.admin@sit.singaporetech.edu.sg")

    empty = admin_client.get("/alerts").get_data(as_text=True)
    selected["name"] = "audit"
    audit = admin_client.get("/alerts?alert=alert-1").get_data(as_text=True)
    selected["name"] = "database"
    database = admin_client.get("/alerts?alert=alert-2").get_data(as_text=True)
    selected["name"] = "generic"
    generic = admin_client.get("/alerts?alert=missing").get_data(as_text=True)

    assert "No active alert findings. Continue scheduled monitoring." in empty
    assert "Preserve evidence and investigate audit-chain integrity" in audit
    assert "Stop routine anchor rotation" in audit
    assert "Preserve database and host evidence" in database
    assert "Review related authentication audit events and source grouping." in database
    assert "Open the alert detail and correlate with safe audit-log entries." in generic
    assert "unknown" in generic
    assert "No related audit event ID in this alert." in generic


def test_alert_manual_delivery_browser_requires_csrf_when_enabled(admin_app, admin_client, monkeypatch):
    remote_addr = "203.0.113.42"
    _admin, admin_secret = _create_staff_identity(
        username="security-admin",
        email="security.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234568",
    )
    calls = []

    def fake_report(*, deliver):
        calls.append(deliver)
        return _delivery_report(delivery={"attempted": bool(deliver), "configured": True, "enabled": True})

    monkeypatch.setattr("app.admin.routes.build_security_alert_report", fake_report)
    _login_admin(
        admin_client,
        admin_secret,
        email="security.admin@sit.singaporetech.edu.sg",
        remote_addr=remote_addr,
    )

    original = admin_app.config["WTF_CSRF_ENABLED"]
    admin_app.config["WTF_CSRF_ENABLED"] = True
    try:
        page = admin_client.get("/alerts", environ_overrides={"REMOTE_ADDR": remote_addr})
        missing_csrf = admin_client.post(
            "/alerts/deliver",
            data={"totp_code": _totp(admin_secret)},
            environ_overrides={"REMOTE_ADDR": remote_addr},
            follow_redirects=False,
        )
        csrf_match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page.get_data(as_text=True))
        assert csrf_match is not None
        delivered = admin_client.post(
            "/alerts/deliver",
            data={"csrf_token": csrf_match.group(1), "totp_code": _totp(admin_secret)},
            environ_overrides={"REMOTE_ADDR": remote_addr},
            follow_redirects=False,
        )
    finally:
        admin_app.config["WTF_CSRF_ENABLED"] = original

    assert page.status_code == 200
    assert 'action="/alerts/deliver"' in page.get_data(as_text=True)
    assert missing_csrf.status_code == 400
    assert delivered.status_code == 303
    assert delivered.headers["Location"].endswith("/alerts")
    assert calls == [False, True]


def test_alert_manual_delivery_reuses_builder_and_audits_delivered(admin_client, monkeypatch):
    remote_addr = "203.0.113.44"
    _admin, admin_secret = _create_staff_identity(
        username="security-admin",
        email="security.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234568",
    )
    event = SecurityAuditEvent(
        event_type="manual_recovery_requested",
        outcome="requested",
        user_id=None,
        ip_address="203.0.113.50",
        user_agent="unit-test",
        correlation_id="alert-request-1",
        session_ref="safe-session-ref",
        event_metadata={"severity": "high", "request_ref": "safe-request-ref"},
        created_at=datetime.now(timezone.utc),
    )
    db.session.add(event)
    db.session.commit()
    secret_header = "Bearer " + "A" * 48
    calls = []

    def fake_report(*, deliver):
        calls.append(deliver)
        assert deliver is True
        return _delivery_report(
            alerts=[
                {
                    "alert_type": "manual_recovery_burst",
                    "severity": "high",
                    "count": 3,
                    "window_seconds": 600,
                    "source": "principal_ref:safe",
                    "generated_at": "2026-06-30T08:15:00+00:00",
                    "latest_event_id": event.id,
                    "reason": secret_header,
                    "authorization": secret_header,
                },
                {
                    "alert_type": "login_failure_burst",
                    "severity": "medium",
                    "count": 4,
                    "window_seconds": 300,
                    "source": secret_header,
                    "generated_at": "2026-06-30T08:15:00+00:00",
                    "latest_event_id": 999999,
                },
            ],
        )

    monkeypatch.setattr("app.admin.routes.build_security_alert_report", fake_report)
    _login_admin(
        admin_client,
        admin_secret,
        email="security.admin@sit.singaporetech.edu.sg",
        remote_addr=remote_addr,
    )

    response = admin_client.post(
        "/alerts/deliver",
        json={"totp_code": _totp(admin_secret)},
        environ_overrides={"REMOTE_ADDR": remote_addr},
    )
    payload = response.get_json()
    body = response.get_data(as_text=True)
    events = db.session.query(SecurityAuditEvent).filter_by(
        event_type="security_alert_delivery",
    ).order_by(SecurityAuditEvent.id).all()

    assert response.status_code == 200
    assert payload["outcome"] == "delivered"
    assert payload["delivery"]["attempted"] is True
    assert payload["delivery"]["delivered"] is True
    assert payload["alerts"][0]["event_url"].endswith(f"/audit-logs/{event.id}")
    assert payload["alerts"][1]["event_url"] == ""
    assert "[redacted]" in body
    assert secret_header not in body
    assert "authorization" not in body.casefold()
    assert calls == [True]
    assert [item.outcome for item in events] == ["requested", "delivered"]
    assert events[-1].event_metadata["delivery_attempted"] is True
    assert events[-1].event_metadata["delivery_configured"] is True


def test_alert_manual_delivery_respects_dedupe_and_returns_safe_json(admin_client, monkeypatch):
    remote_addr = "203.0.113.45"
    _admin, admin_secret = _create_staff_identity(
        username="security-admin",
        email="security.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234568",
    )

    def fake_report(*, deliver):
        assert deliver is True
        return _delivery_report(
            deliverable_alert_count=0,
            delivery={
                "attempted": False,
                "configured": True,
                "enabled": True,
                "delivered": True,
                "deduped": True,
            },
            dedupe={"enabled": True, "ttl_seconds": 300, "suppressed": 1},
        )

    monkeypatch.setattr("app.admin.routes.build_security_alert_report", fake_report)
    _login_admin(
        admin_client,
        admin_secret,
        email="security.admin@sit.singaporetech.edu.sg",
        remote_addr=remote_addr,
    )

    response = admin_client.post(
        "/alerts/deliver",
        json={"totp_code": _totp(admin_secret)},
        environ_overrides={"REMOTE_ADDR": remote_addr},
    )
    payload = response.get_json()
    outcomes = [
        item.outcome
        for item in db.session.query(SecurityAuditEvent)
        .filter_by(event_type="security_alert_delivery")
        .order_by(SecurityAuditEvent.id)
    ]

    assert response.status_code == 200
    assert payload["outcome"] == "deduped"
    assert payload["dedupe"]["suppressed"] == 1
    assert outcomes == ["requested", "deduped"]


def test_alert_manual_delivery_blocks_invalid_totp(admin_client):
    remote_addr = "203.0.113.46"
    _admin, admin_secret = _create_staff_identity(
        username="security-admin",
        email="security.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234568",
    )
    _login_admin(
        admin_client,
        admin_secret,
        email="security.admin@sit.singaporetech.edu.sg",
        remote_addr=remote_addr,
    )
    bad_code = "000000" if _totp(admin_secret) != "000000" else "111111"

    blocked = admin_client.post(
        "/alerts/deliver",
        json={"totp_code": bad_code},
        environ_overrides={"REMOTE_ADDR": remote_addr},
    )
    events = db.session.query(SecurityAuditEvent).filter_by(
        event_type="security_alert_delivery",
    ).order_by(SecurityAuditEvent.id).all()

    assert blocked.status_code == 403
    assert blocked.get_json() == {"error": "Fresh MFA verification is required"}
    assert [item.outcome for item in events] == ["blocked"]
    assert events[0].event_metadata["reason"] == "invalid_totp_step_up"


def test_alert_manual_delivery_audits_configuration_failure(admin_client, monkeypatch):
    from app.security.alerts import AlertConfigurationError

    remote_addr = "203.0.113.47"
    _admin, admin_secret = _create_staff_identity(
        username="security-admin",
        email="security.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234568",
    )
    _login_admin(
        admin_client,
        admin_secret,
        email="security.admin@sit.singaporetech.edu.sg",
        remote_addr=remote_addr,
    )

    def fail_report(*, deliver):
        assert deliver is True
        raise AlertConfigurationError("SECURITY_ALERT_WEBHOOK_URL_FILE is required")

    monkeypatch.setattr("app.admin.routes.build_security_alert_report", fail_report)
    failed = admin_client.post(
        "/alerts/deliver",
        json={"totp_code": _totp(admin_secret)},
        environ_overrides={"REMOTE_ADDR": remote_addr},
    )
    events = db.session.query(SecurityAuditEvent).filter_by(
        event_type="security_alert_delivery",
    ).order_by(SecurityAuditEvent.id).all()

    assert failed.status_code == 503
    assert failed.get_json() == {"error": "Security alert delivery is unavailable"}
    assert [item.outcome for item in events] == ["requested", "failed"]
    assert events[-1].event_metadata["reason"] == "alert_configuration_error"
    assert events[-1].event_metadata["error_type"] == "AlertConfigurationError"


def test_admin_templates_do_not_render_inline_script_or_sensitive_fields():
    template_dir = Path("app/templates/admin")
    combined = "\n".join(path.read_text(encoding="utf-8") for path in template_dir.glob("*.html"))
    inline_scripts = [
        script
        for script in re.findall(r"<script\b([^>]*)>", combined, flags=re.IGNORECASE)
        if " src=" not in script
    ]

    assert inline_scripts == []
    assert "|safe" not in combined
    assert "unsafe-inline" not in combined
    for forbidden in (
        "password_hash",
        "mfa_secret_ciphertext",
        "mfa_secret_nonce",
        "token_hash",
        "invite.token",
        "csrf_token() }}\" data",
    ):
        assert forbidden not in combined
