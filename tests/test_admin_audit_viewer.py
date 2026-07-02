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
    displayed_event = filtered_payload["events"][0]
    assert displayed_event["created_at_display"] == "2026-06-28 12:00:00 UTC"
    assert displayed_event["created_at_utc"].startswith("2026-06-28T12:00:00")
    assert displayed_event["activity"] == "Staff invite created"
    assert displayed_event["event_description"] == "A staff/admin invite was created."
    assert displayed_event["actor_role"] == "admin"
    assert displayed_event["actor_summary"] == f"user:{admin.id} (admin, security.admin@sit.singaporetech.edu.sg)"
    assert displayed_event["source_kind"] == "network"
    assert displayed_event["source_display"] == "203.0.113.10"
    assert displayed_event["request_id"] == "audit-request-1"
    assert displayed_event["target_ref"] == "target-ref-123"
    assert "staff_invite_created" in filtered_payload["event_type_options"]
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
    assert "Other safe metadata" in body
    assert "Hash chain" in body
    assert "Investigation Summary" in body
    assert "Field Legend" in body
    assert payload["event"]["activity"] == "Unsafe legacy metadata"
    assert payload["event"]["event_description"] == "Recorded audit event `unsafe_legacy_metadata`."
    assert payload["event"]["field_legend"]["Actor"].startswith("Safe actor identity")


def test_audit_actor_summary_handles_unavailable_and_customer_actors(admin_client):
    admin, admin_secret = _create_identity(
        username="security-admin",
        email="security.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234567",
    )
    customer, _customer_secret = _create_identity(
        username="audit-customer",
        email="audit.customer@example.com",
        account_type="customer",
        phone_number="91234568",
    )
    unavailable = _audit_event(
        event_type="manual_recovery_requested",
        user_id=999999,
        metadata={"severity": "low"},
    )
    customer_event = _audit_event(
        event_type="manual_recovery_requested",
        user_id=customer.id,
        metadata={"severity": "low"},
    )
    _login_admin(admin_client, admin_secret, "security.admin@sit.singaporetech.edu.sg")

    unavailable_payload = admin_client.get(
        f"/audit-logs/{unavailable.id}",
        headers={"Accept": "application/json"},
    ).get_json()
    customer_payload = admin_client.get(
        f"/audit-logs/{customer_event.id}",
        headers={"Accept": "application/json"},
    ).get_json()

    assert unavailable_payload["event"]["actor_summary"] == "user:999999 (unavailable)"
    assert customer_payload["event"]["actor_summary"] == f"user:{customer.id} (customer)"
    assert "audit.customer@example.com" not in str(customer_payload)


def test_audit_viewer_renders_dropdown_timestamps_and_system_probe_source(admin_client):
    admin, admin_secret = _create_identity(
        username="security-admin",
        email="security.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234567",
    )
    event = _audit_event(
        event_type="privilege_probe",
        user_id=None,
        metadata={"severity": "critical", "reason": "runtime_db_privilege_check"},
        created_at=datetime(2026, 6, 30, 8, 15, tzinfo=timezone.utc),
        ip_address="privilege-check",
        correlation_id="probe-request-1",
    )
    _login_admin(admin_client, admin_secret, "security.admin@sit.singaporetech.edu.sg")

    listing = admin_client.get("/audit-logs")
    detail = admin_client.get(f"/audit-logs/{event.id}")
    listing_body = listing.get_data(as_text=True)
    detail_body = detail.get_data(as_text=True)

    assert listing.status_code == 200
    assert '<select id="audit-event-type" name="event_type">' in listing_body
    assert "privilege_probe" in listing_body
    assert "2026-06-30 08:15:00 UTC" in listing_body
    assert "system_probe: Runtime privilege probe" in listing_body
    assert "privilege-check" not in listing_body
    assert detail.status_code == 200
    assert "Runtime privilege probe" in detail_body
    assert "Blocked or failed outcomes should stop deployment" in detail_body
    assert "Runtime privilege probe" in detail_body
    assert "Security decision" in detail_body


def test_audit_detail_uses_metadata_role_source_and_grouped_safe_fields(admin_client):
    admin, admin_secret = _create_identity(
        username="security-admin",
        email="security.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234567",
    )
    event = _audit_event(
        event_type="host_deploy_wrapper",
        user_id=None,
        metadata={
            "actor_role": "root_admin",
            "source_kind": "deployment",
            "source_display": "Deployment wrapper",
            "request_method": "POST",
            "target_staff_ref": "safe-target-ref",
            "result_count": 2,
            "custom_note": "operator summary only",
        },
        created_at=datetime(2026, 6, 30, 9, 15, tzinfo=timezone.utc),
        ip_address="deployment",
        correlation_id="deploy-request-1",
    )
    scheduled = _audit_event(
        event_type="security_alert_scheduler",
        user_id=None,
        metadata={"severity": "medium"},
        ip_address="scheduler",
        correlation_id="scheduler-request-1",
    )
    source_less = _audit_event(
        event_type="legacy_system_event",
        user_id=None,
        metadata={"severity": "low"},
        ip_address="",
        correlation_id="source-less-request-1",
    )
    _login_admin(admin_client, admin_secret, "security.admin@sit.singaporetech.edu.sg")

    json_response = admin_client.get(
        f"/audit-logs/{event.id}",
        headers={"Accept": "application/json"},
    )
    scheduled_response = admin_client.get(
        f"/audit-logs/{scheduled.id}",
        headers={"Accept": "application/json"},
    )
    source_less_response = admin_client.get(
        f"/audit-logs/{source_less.id}",
        headers={"Accept": "application/json"},
    )
    html_response = admin_client.get(f"/audit-logs/{event.id}")
    payload = json_response.get_json()["event"]
    scheduled_payload = scheduled_response.get_json()["event"]
    source_less_payload = source_less_response.get_json()["event"]
    body = html_response.get_data(as_text=True)

    assert payload["actor_role"] == "root_admin"
    assert payload["activity"] == "Deployment wrapper check"
    assert payload["investigation_hint"] == "Correlate with GitHub run evidence and host-side deployment logs."
    assert payload["source_kind"] == "deployment"
    assert payload["source_display"] == "Deployment wrapper"
    assert payload["target_ref"] == "safe-target-ref"
    assert payload["metadata_groups"]["Actor and session"]["actor_role"] == "root_admin"
    assert payload["metadata_groups"]["Request and source"]["request_method"] == "POST"
    assert payload["metadata_groups"]["Target"]["target_staff_ref"] == "safe-target-ref"
    assert payload["metadata_groups"]["Result and system"]["result_count"] == 2
    assert payload["metadata_groups"]["Other safe metadata"]["custom_note"] == "operator summary only"
    assert scheduled_payload["source_kind"] == "system"
    assert scheduled_payload["source_display"] == "System or scheduled control"
    assert source_less_payload["source_kind"] == "system"
    assert source_less_payload["source_display"] == "System"
    assert "Deployment wrapper" in body
    assert "Actor and session" in body
    assert "Request and source" in body
    assert "Result and system" in body


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
