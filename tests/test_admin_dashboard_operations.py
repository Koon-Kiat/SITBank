from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pyotp
import pytest

from app.extensions import db
from app.models import SecurityAuditEvent, User
from app.security.crypto import encrypt_mfa_secret
from app.security.passwords import hash_password
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


def _login_admin(client, secret: str, email: str = ROOT_EMAIL):
    password_response = client.post(
        "/login",
        json={"workplace_email": email, "password": ROOT_PASSWORD},
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
    assert "security_keys" not in staff_body
    assert "webauthn/register" not in staff_body.casefold()
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
    assert target.account_status == "setup_pending"
    assert target.mfa_enabled is False
    assert target.mfa_secret_nonce is None
    assert target.mfa_secret_ciphertext is None
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="staff_account_deactivated",
        outcome="success",
    ).count() == 1
    deactivation_event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="staff_account_deactivated",
        outcome="success",
    ).one()
    assert deactivation_event.event_metadata["revoked_sessions"] == 0
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="staff_activation_reset",
        outcome="success",
    ).count() == 1


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
    _staff, staff_secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        account_type="staff",
        phone_number="91234567",
    )
    _login_admin(admin_client, staff_secret, email="bank.staff@sit.singaporetech.edu.sg")
    assert admin_client.get("/alerts").status_code == 403

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
    assert "security_keys" not in combined
    assert "webauthn" not in combined.casefold()
    assert "passkey" not in combined.casefold()
