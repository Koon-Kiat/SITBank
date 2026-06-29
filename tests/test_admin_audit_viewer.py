from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyotp
import pytest

from app.extensions import db
from app.models import SecurityAuditEvent, User
from app.security.crypto import encrypt_mfa_secret
from app.security.passwords import hash_password
from conftest import TestConfig


ROOT_PASSWORD = "correct horse battery staple"
RAW_SECRET = "SecretTokenValue1234567890SecretTokenValue1234567890SecretTokenValue1234567890"
_FIXED_TOTP_TIME = int(time.time())


@pytest.fixture(autouse=True)
def freeze_totp_verifier_time(monkeypatch):
    global _FIXED_TOTP_TIME
    _FIXED_TOTP_TIME = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: _FIXED_TOTP_TIME)


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


def _create_identity(
    *,
    username: str,
    email: str,
    account_type: str,
    phone_number: str,
) -> tuple[User, str]:
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(ROOT_PASSWORD),
        account_type=account_type,
        account_status="active",
        full_name=username.replace("-", " ").title(),
        phone_number=phone_number,
        account_number="100000001" if account_type == "customer" else None,
        workplace_email_verified_at=datetime.now(timezone.utc) if account_type != "customer" else None,
        mfa_enabled=False,
    )
    db.session.add(user)
    db.session.flush()
    secret = pyotp.random_base32(length=32)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(secret, user.id)
    user.mfa_enabled = True
    db.session.commit()
    return user, secret


def _login_admin(client, secret: str, email: str):
    primary = client.post(
        "/login",
        json={"workplace_email": email, "password": ROOT_PASSWORD},
    )
    assert primary.status_code == 200
    verify = client.post(
        "/mfa/verify",
        json={"totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(_FIXED_TOTP_TIME)},
    )
    assert verify.status_code == 200


def _audit_event(
    *,
    event_type: str,
    outcome: str = "success",
    user_id: int | None = None,
    metadata: dict | None = None,
    created_at: datetime | None = None,
    ip_address: str = "203.0.113.10",
    correlation_id: str = "audit-request-1",
    session_ref: str = "safe-session-ref",
) -> SecurityAuditEvent:
    event = SecurityAuditEvent(
        event_type=event_type,
        outcome=outcome,
        user_id=user_id,
        ip_address=ip_address,
        user_agent="unit-test",
        correlation_id=correlation_id,
        session_ref=session_ref,
        event_metadata=metadata or {},
        created_at=created_at or datetime.now(timezone.utc),
    )
    db.session.add(event)
    db.session.commit()
    return event


def test_audit_viewer_authorization_denies_unauthenticated_customer_and_staff(admin_client):
    unauthenticated = admin_client.get("/audit-logs")
    customer, _customer_secret = _create_identity(
        username="customer-user",
        email="customer@example.com",
        account_type="customer",
        phone_number="91234567",
    )
    with admin_client.session_transaction() as sess:
        sess["user_id"] = customer.id
    customer_response = admin_client.get("/audit-logs")
    admin_client.post("/logout")

    _staff, staff_secret = _create_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        account_type="staff",
        phone_number="91234568",
    )
    _login_admin(admin_client, staff_secret, "bank.staff@sit.singaporetech.edu.sg")
    staff_response = admin_client.get("/audit-logs")

    assert unauthenticated.status_code == 401
    assert customer_response.status_code == 403
    assert staff_response.status_code == 403
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="admin_role_authorization",
        outcome="blocked",
    ).count() == 1


def test_audit_viewer_filters_sorting_pagination_and_safe_search(admin_client):
    admin, admin_secret = _create_identity(
        username="security-admin",
        email="security.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234567",
    )
    other, _other_secret = _create_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        account_type="staff",
        phone_number="91234568",
    )
    matching = _audit_event(
        event_type="staff_invite_created",
        user_id=admin.id,
        metadata={
            "severity": "high",
            "target_staff_ref": "target-ref-123",
            "note": "visible staff invite review",
        },
        created_at=datetime(2026, 6, 28, 12, 0, tzinfo=timezone.utc),
        correlation_id="audit-request-1",
    )
    _audit_event(
        event_type="login",
        outcome="failure",
        user_id=other.id,
        metadata={"severity": "low", "target_staff_ref": "other-target"},
        created_at=datetime(2026, 6, 29, 12, 0, tzinfo=timezone.utc),
        ip_address="203.0.113.99",
        correlation_id="audit-request-2",
    )
    _login_admin(admin_client, admin_secret, "security.admin@sit.singaporetech.edu.sg")

    filtered = admin_client.get(
        "/audit-logs?"
        "event_type=staff_invite_created&actor="
        f"{admin.id}&target=target-ref-123&role=admin&severity=high&outcome=success&"
        "request_id=audit-request-1&ip_address=203.0.113.10&"
        "from=2026-06-28T00:00:00Z&to=2026-06-28T23:59:59Z&"
        "sort=event_type&direction=asc&page=1&per_page=1",
        headers={"Accept": "application/json"},
    )
    invalid = admin_client.get(
        "/audit-logs?sort=drop_table&direction=sideways&page=-4&per_page=500&outcome=made_up",
        headers={"Accept": "application/json"},
    )
    metadata_search = admin_client.get(
        "/audit-logs?q=visible",
        headers={"Accept": "application/json"},
    )
    field_search = admin_client.get(
        "/audit-logs?q=staff_invite_created",
        headers={"Accept": "application/json"},
    )

    assert filtered.status_code == 200
    filtered_payload = filtered.get_json()
    assert [event["id"] for event in filtered_payload["events"]] == [matching.id]
    assert filtered_payload["total"] == 1
    assert filtered_payload["total_pages"] == 1
    assert invalid.status_code == 200
    invalid_payload = invalid.get_json()
    assert invalid_payload["sort"] == "timestamp"
    assert invalid_payload["direction"] == "desc"
    assert invalid_payload["page"] == 1
    assert invalid_payload["per_page"] == 100
    assert invalid_payload["filters"]["outcome"] == ""
    assert metadata_search.status_code == 200
    assert all(event["event_type"] != "staff_invite_created" for event in metadata_search.get_json()["events"])
    assert field_search.status_code == 200
    assert any(event["event_type"] == "staff_invite_created" for event in field_search.get_json()["events"])
    assert "sql" not in invalid.get_data(as_text=True).casefold()


def test_audit_event_detail_redacts_existing_unsafe_metadata_and_escapes_html(admin_client):
    admin, admin_secret = _create_identity(
        username="security-admin",
        email="security.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234567",
    )
    event = _audit_event(
        event_type="unsafe_legacy_metadata",
        user_id=admin.id,
        metadata={
            "note": RAW_SECRET,
            "display_name": "<script>alert(1)</script>",
            "invite_token": "plain-invite-token",
            "nested": {"visible": RAW_SECRET, "target_staff_ref": "safe-ref"},
        },
    )
    _login_admin(admin_client, admin_secret, "security.admin@sit.singaporetech.edu.sg")

    detail = admin_client.get(f"/audit-logs/{event.id}")
    payload = admin_client.get(f"/audit-logs/{event.id}", headers={"Accept": "application/json"}).get_json()
    body = detail.get_data(as_text=True)

    assert detail.status_code == 200
    assert RAW_SECRET not in body
    assert RAW_SECRET not in str(payload)
    assert "plain-invite-token" not in body
    assert "invite_token" not in body
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert payload["event"]["metadata"]["note"] == "[redacted]"
    assert payload["event"]["metadata"]["nested"]["visible"] == "[redacted]"
    assert payload["event"]["metadata"]["nested"]["target_staff_ref"] == "safe-ref"


def test_audit_viewer_is_read_only_and_template_avoids_safe_filter(admin_client):
    admin, admin_secret = _create_identity(
        username="security-admin",
        email="security.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234567",
    )
    event = _audit_event(event_type="read_only_check", user_id=admin.id)
    _login_admin(admin_client, admin_secret, "security.admin@sit.singaporetech.edu.sg")

    post_list = admin_client.post("/audit-logs", json={"event_type": "mutated"})
    delete_detail = admin_client.delete(f"/audit-logs/{event.id}")
    event_count = db.session.query(SecurityAuditEvent).filter_by(event_type="read_only_check").count()
    templates = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            Path("app/templates/admin/audit_logs.html"),
            Path("app/templates/admin/audit_log_detail.html"),
        )
    )

    assert post_list.status_code == 405
    assert delete_detail.status_code == 405
    assert event_count == 1
    assert "|safe" not in templates
