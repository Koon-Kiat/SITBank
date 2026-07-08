from __future__ import annotations

import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pyotp
import pytest
from sqlalchemy import func

from app.auth.password_reset import (
    complete_manual_recovery_request,
    expire_manual_recovery_requests,
    generate_recovery_codes_for_user,
    transition_manual_recovery_request,
)
from app.auth.recovery_codes import consume_recovery_code, unused_recovery_code_count
import app.auth.services as auth_services
from app.auth.services import AuthError
from app.extensions import db
from app.models import ManualRecoveryRequest, PasswordResetToken, RecoveryCode, SecurityAuditEvent, SupportTicket, User
from app.security.crypto import encrypt_mfa_secret
from app.security.email import password_reset_outbox
from app.security.passwords import PASSWORD_MAX_CHARS, PASSWORD_MIN_LENGTH, hash_password, verify_password
from app.security.session_hmac import active_hmac_hex


VALID_PASSWORD = "Correct-Horse-Battery-Staple-2026!"
NEW_PASSWORD = "Reset-Correct-Horse-Battery-Staple-2026!"
ORIGIN = {"Origin": "https://sitbank.pp.ua"}
TOTP_TEST_TIMESTAMP = 1_803_988_800


def _create_user(username: str, email: str, password: str = VALID_PASSWORD,
                 full_name: str = "Test User", phone_number: str = "91234567") -> User:
    account_number = "".join(str(secrets.randbelow(10)) for _ in range(12))
    user = User(username=username, email=email, password_hash=hash_password(password),
                full_name=full_name, phone_number=phone_number, account_number=account_number)
    db.session.add(user)
    db.session.commit()
    return user


def _create_totp_user(username: str, email: str, full_name: str = "Test User", phone_number: str = "91234567") -> tuple[User, str]:
    user = _create_user(username, email, full_name=full_name, phone_number=phone_number)
    secret = pyotp.random_base32(length=32)
    nonce, ciphertext = encrypt_mfa_secret(secret, user.id)
    user.mfa_secret_nonce = nonce
    user.mfa_secret_ciphertext = ciphertext
    user.mfa_enabled = True
    db.session.commit()
    return user, secret


def _totp_code_at_frozen_time(monkeypatch, secret: str) -> str:
    monkeypatch.setattr(
        auth_services,
        "time",
        SimpleNamespace(time=lambda: TOTP_TEST_TIMESTAMP),
    )
    return pyotp.TOTP(secret).at(TOTP_TEST_TIMESTAMP)


def _request_reset(client, email: str):
    return client.post("/auth/password-reset/request", json={"email": email})


def _reset_token(app) -> str:
    with app.app_context():
        outbox = password_reset_outbox()
        assert len(outbox) == 1
        match = re.search(r"https://[^\s]+/reset-password\?token=([A-Za-z0-9_.-]+)", outbox[0]["body"])
        assert match
        return parse_qs(urlparse(f"https://example.test/?token={match.group(1)}").query)["token"][0]


def _latest_reset_token(app) -> str:
    with app.app_context():
        for item in reversed(password_reset_outbox()):
            match = re.search(r"https://[^\s]+/reset-password\?token=([A-Za-z0-9_.-]+)", item["body"])
            if match:
                return parse_qs(urlparse(f"https://example.test/?token={match.group(1)}").query)["token"][0]
    raise AssertionError("password reset email was not sent")


def _exchange(client, token: str):
    return client.post("/auth/password-reset/exchange", json={"token": token})


def _begin_no_mfa_reset(app, client, *, username: str, email: str, full_name: str = "Test User", phone_number: str = "91234567") -> int:
    with app.app_context():
        user = _create_user(username, email, full_name=full_name, phone_number=phone_number)
        user_id = user.id

    assert _request_reset(client, email).status_code == 200
    token = _reset_token(app)
    exchanged = _exchange(client, token)
    assert exchanged.status_code == 200, exchanged.get_data(as_text=True)
    assert exchanged.get_json()["mfa_required"] == "none"
    return user_id


def test_forgot_password_response_is_generic_and_token_is_hashed(app, client):
    with app.app_context():
        _create_user("reset01", "reset01@example.com")

    known = _request_reset(client, "reset01@example.com")
    unknown = _request_reset(client, "missing@example.com")

    assert known.status_code == 200
    assert unknown.status_code == 200
    assert known.get_json() == unknown.get_json()
    assert known.get_json()["message"] == "If an account is linked to that email, a reset link has been sent. Check your inbox."

    token = _reset_token(app)
    selector, verifier = token.split(".", 1)
    with app.app_context():
        reset_token = db.session.execute(
            db.select(PasswordResetToken).where(PasswordResetToken.selector == selector)
        ).scalar_one()
        assert reset_token.verifier_hmac
        assert reset_token.verifier_hmac != verifier
        audit_text = json.dumps(
            [
                {
                    "event_type": event.event_type,
                    "metadata": event.event_metadata,
                }
                for event in db.session.execute(db.select(SecurityAuditEvent)).scalars()
            ],
            sort_keys=True,
        )
        assert token not in audit_text
        assert verifier not in audit_text


def test_reset_token_exchanges_once_into_tokenless_transaction(app, client):
    with app.app_context():
        _create_user("reset02", "reset02@example.com")

    _request_reset(client, "reset02@example.com")
    token = _reset_token(app)

    exchanged = _exchange(client, token)
    replay = _exchange(client, token)
    dashboard = client.get("/dashboard", follow_redirects=False)
    transaction = client.get("/auth/password-reset/transaction")

    assert exchanged.status_code == 200
    assert exchanged.get_json()["mfa_required"] == "none"
    assert replay.status_code == 401
    assert dashboard.status_code == 302
    assert dashboard.headers["Location"].endswith("/login")
    assert transaction.status_code == 200
    assert "token" not in transaction.get_data(as_text=True).casefold()


def test_no_mfa_password_reset_does_not_auto_login_and_forces_mfa_on_next_login(app, client):
    with app.app_context():
        user = _create_user("reset03", "reset03@example.com")
        old_hash = user.password_hash

    _request_reset(client, "reset03@example.com")
    token = _reset_token(app)
    assert _exchange(client, token).status_code == 200

    completed = client.post(
        "/auth/password-reset/complete",
        json={"new_password": NEW_PASSWORD, "confirm_new_password": NEW_PASSWORD},
    )
    dashboard = client.get("/dashboard", follow_redirects=False)
    login = client.post("/auth/login", json={"identifier": "reset03", "password": NEW_PASSWORD})

    assert completed.status_code == 200
    assert dashboard.status_code == 302
    assert dashboard.headers["Location"].endswith("/login")
    assert login.status_code == 200
    assert login.get_json()["mfa_setup_required"] is True
    with app.app_context():
        user = db.session.get(User, user.id)
        assert user is not None
        assert user.password_hash != old_hash
        assert verify_password(NEW_PASSWORD, user.password_hash)


def test_password_reset_rejects_recent_password_history(app, client, monkeypatch):
    monkeypatch.setattr("app.security.passwords._is_password_pwned_by_hibp", lambda _password: False)
    with app.app_context():
        user = _create_user("resethistory", "resethistory@example.com")
        user_id = user.id

    _request_reset(client, "resethistory@example.com")
    token = _latest_reset_token(app)
    assert _exchange(client, token).status_code == 200
    first_completed = client.post(
        "/auth/password-reset/complete",
        json={"new_password": NEW_PASSWORD, "confirm_new_password": NEW_PASSWORD},
    )
    assert first_completed.status_code == 200

    _request_reset(client, "resethistory@example.com")
    second_token = _latest_reset_token(app)
    assert _exchange(client, second_token).status_code == 200
    reused = client.post(
        "/auth/password-reset/complete",
        json={"new_password": VALID_PASSWORD, "confirm_new_password": VALID_PASSWORD},
    )

    assert reused.status_code == 400
    with app.app_context():
        user = db.session.get(User, user_id)
        assert user is not None
        assert verify_password(NEW_PASSWORD, user.password_hash)


def test_password_reset_accepts_256_character_password_without_truncation(app, client, monkeypatch):
    monkeypatch.setattr("app.security.passwords._is_password_pwned_by_hibp", lambda _password: False)
    max_length_password = ("A" * (PASSWORD_MAX_CHARS - 1)) + "Z"
    truncated_variant = "A" * PASSWORD_MAX_CHARS
    user_id = _begin_no_mfa_reset(app, client, username="resetmax", email="resetmax@example.com")

    completed = client.post(
        "/auth/password-reset/complete",
        json={"new_password": max_length_password, "confirm_new_password": max_length_password},
    )

    assert completed.status_code == 200, completed.get_data(as_text=True)
    with app.app_context():
        user = db.session.get(User, user_id)
        assert user is not None
        assert verify_password(max_length_password, user.password_hash)
        assert not verify_password(truncated_variant, user.password_hash)


def test_password_reset_completion_uses_required_audit_writer(app, client, monkeypatch):
    from app.auth import password_reset

    calls = []

    def required_audit(event_type, outcome, **kwargs):
        calls.append((event_type, outcome, kwargs))
        db.session.commit()

    monkeypatch.setattr(password_reset, "audit_event_required", required_audit)
    user_id = _begin_no_mfa_reset(app, client, username="resetaudit", email="resetaudit@example.com")

    completed = client.post(
        "/auth/password-reset/complete",
        json={"new_password": NEW_PASSWORD, "confirm_new_password": NEW_PASSWORD},
    )

    assert completed.status_code == 200, completed.get_data(as_text=True)
    assert ("password_reset_completed", "success") in [(call[0], call[1]) for call in calls]
    with app.app_context():
        user = db.session.get(User, user_id)
        assert user is not None
        assert verify_password(NEW_PASSWORD, user.password_hash)

def test_password_reset_completion_required_audit_failure_does_not_commit_password(app, client, monkeypatch):
    from app.auth import password_reset
    from app.security.audit import AuditWriteError

    user_id = _begin_no_mfa_reset(app, client, username="resetauditfail", email="resetauditfail@example.com")
    original_hash = db.session.get(User, user_id).password_hash

    def fail_required_audit(*_args, **_kwargs):
        raise AuditWriteError("required audit unavailable")

    monkeypatch.setattr(password_reset, "audit_event_required", fail_required_audit)
    app.config["PROPAGATE_EXCEPTIONS"] = True

    with pytest.raises(AuditWriteError):
        client.post(
            "/auth/password-reset/complete",
            json={"new_password": NEW_PASSWORD, "confirm_new_password": NEW_PASSWORD},
        )

    db.session.rollback()
    user = db.session.get(User, user_id)
    assert user.password_hash == original_hash
    assert not verify_password(NEW_PASSWORD, user.password_hash)
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="password_reset_completed").count() == 0


def test_password_reset_accepts_8_character_password(app, client, monkeypatch):
    monkeypatch.setattr("app.security.passwords._is_password_pwned_by_hibp", lambda _password: False)
    minimum_password = "Abcdef12"
    user_id = _begin_no_mfa_reset(app, client, username="resetmin", email="resetmin@example.com")

    completed = client.post(
        "/auth/password-reset/complete",
        json={"new_password": minimum_password, "confirm_new_password": minimum_password},
    )

    assert len(minimum_password) == PASSWORD_MIN_LENGTH
    assert completed.status_code == 200, completed.get_data(as_text=True)
    with app.app_context():
        user = db.session.get(User, user_id)
        assert user is not None
        assert verify_password(minimum_password, user.password_hash)


def test_password_reset_uses_configured_password_minimum(app, client, monkeypatch):
    monkeypatch.setattr("app.security.passwords._is_password_pwned_by_hibp", lambda _password: False)
    app.config["PASSWORD_MIN_LENGTH"] = 12
    user_id = _begin_no_mfa_reset(app, client, username="resetmincfg", email="resetmincfg@example.com")

    too_short = client.post(
        "/auth/password-reset/complete",
        json={"new_password": "Abcdef12345", "confirm_new_password": "Abcdef12345"},
    )

    assert too_short.status_code == 400
    assert too_short.get_json() == {"error": "Password must be at least 12 characters"}
    with app.app_context():
        user = db.session.get(User, user_id)
        assert user is not None
        assert verify_password(VALID_PASSWORD, user.password_hash)


def test_password_reset_rejects_passwords_over_256_characters(app, client):
    user_id = _begin_no_mfa_reset(app, client, username="resettoo", email="resettoo@example.com")
    oversized_password = "A" * (PASSWORD_MAX_CHARS + 1)

    completed = client.post(
        "/auth/password-reset/complete",
        json={"new_password": oversized_password, "confirm_new_password": oversized_password},
    )

    assert completed.status_code == 400
    assert "at most 256 characters" in completed.get_data(as_text=True)
    with app.app_context():
        user = db.session.get(User, user_id)
        assert user is not None
        assert verify_password(VALID_PASSWORD, user.password_hash)


def test_password_reset_rejects_local_common_password(app, client, tmp_path):
    from app.security import passwords as password_module

    common_password = "common reset phrase 2026"
    blocklist = tmp_path / "common-passwords.txt"
    blocklist.write_text(f"{common_password}\n", encoding="utf-8")
    app.config["COMMON_PASSWORDS_PATH"] = str(blocklist)
    password_module._load_common_passwords.cache_clear()
    try:
        _begin_no_mfa_reset(app, client, username="resetcommon", email="resetcommon@example.com")
        completed = client.post(
            "/auth/password-reset/complete",
            json={"new_password": common_password, "confirm_new_password": common_password},
        )
    finally:
        password_module._load_common_passwords.cache_clear()

    assert completed.status_code == 400
    assert "Password is too common. Please try again" in completed.get_data(as_text=True)


def test_password_reset_rejects_live_breached_password(app, client, monkeypatch):
    breached_password = "breached reset phrase 2026"
    monkeypatch.setattr("app.security.passwords._is_password_pwned_by_hibp", lambda _password: True)
    _begin_no_mfa_reset(app, client, username="resetbreach", email="resetbreach@example.com")

    completed = client.post(
        "/auth/password-reset/complete",
        json={"new_password": breached_password, "confirm_new_password": breached_password},
    )

    assert completed.status_code == 400
    assert "Password is too common. Please try again" in completed.get_data(as_text=True)


def test_totp_user_must_verify_totp_before_password_reset(app, client, monkeypatch):
    with app.app_context():
        _user, secret = _create_totp_user("reset04", "reset04@example.com")

    _request_reset(client, "reset04@example.com")
    token = _reset_token(app)
    exchanged = _exchange(client, token)
    blocked = client.post(
        "/auth/password-reset/complete",
        json={"new_password": NEW_PASSWORD, "confirm_new_password": NEW_PASSWORD},
    )
    verified = client.post(
        "/auth/password-reset/mfa/totp",
        json={"totp_code": _totp_code_at_frozen_time(monkeypatch, secret)},
    )
    completed = client.post(
        "/auth/password-reset/complete",
        json={"new_password": NEW_PASSWORD, "confirm_new_password": NEW_PASSWORD},
    )

    assert exchanged.status_code == 200
    assert exchanged.get_json()["mfa_required"] == "totp"
    assert blocked.status_code == 403
    assert verified.status_code == 200
    assert verified.get_json()["mfa_verified"] is True
    assert completed.status_code == 200


def test_password_reset_totp_replay_rejects_without_transaction_failure(app, client, monkeypatch):
    with app.app_context():
        _user, secret = _create_totp_user("resetreplay", "resetreplay@example.com")

    code = _totp_code_at_frozen_time(monkeypatch, secret)
    _request_reset(client, "resetreplay@example.com")
    assert _exchange(client, _reset_token(app)).status_code == 200
    verified = client.post("/auth/password-reset/mfa/totp", json={"totp_code": code})

    replay_client = app.test_client()
    _request_reset(replay_client, "resetreplay@example.com")
    assert _exchange(replay_client, _latest_reset_token(app)).status_code == 200
    replay = replay_client.post("/auth/password-reset/mfa/totp", json={"totp_code": code})

    assert verified.status_code == 200
    assert replay.status_code == 401
    with app.app_context():
        assert db.session.query(SecurityAuditEvent).filter_by(
            event_type="password_reset_mfa_failed",
            outcome="failure",
        ).one().event_metadata == {"factor": "totp", "reason": "totp_replay"}


def test_password_reset_totp_only_ui_shows_authenticator_recovery_code_method(app, client):
    with app.app_context():
        _user, _secret = _create_totp_user("resettotponly", "resettotponly@example.com")

    _request_reset(client, "resettotponly@example.com")
    token = _reset_token(app)
    exchanged = _exchange(client, token)
    page = client.get("/reset-password/continue")
    markup = page.get_data(as_text=True)

    assert exchanged.status_code == 200
    assert exchanged.get_json()["mfa_required"] == "totp"
    assert exchanged.get_json()["available_mfa_methods"] == ["totp"]
    assert "Authenticator code" in markup
    assert "Use a recovery code" not in markup


def test_admin_like_customer_domain_reset_fails_closed(app, client):
    with app.app_context():
        _create_user("admin", "admin@example.com")

    response = _request_reset(client, "admin@example.com")

    assert response.status_code == 200
    with app.app_context():
        assert password_reset_outbox() == []
        assert db.session.execute(db.select(PasswordResetToken)).first() is None


def test_manual_recovery_request_does_not_freeze_or_unlock_account(app, client):
    with app.app_context():
        user = _create_user("reset06", "reset06@example.com")
        user_id = user.id

    response = client.post("/auth/account-recovery", json={"identifier": "reset06@example.com"})

    assert response.status_code == 200
    with app.app_context():
        user = db.session.get(User, user_id)
        request_record = db.session.execute(db.select(ManualRecoveryRequest)).scalar_one()
        assert user is not None
        assert user.is_frozen is False
        assert user.security_locked_at is None
        assert request_record.user_id == user.id
        assert request_record.status == "pending"


def test_manual_recovery_request_stores_optional_reason_without_leaking_to_audit(app, client):
    with app.app_context():
        user = _create_user("reason01", "reason01@example.com")
        user_id = user.id

    response = client.post(
        "/auth/account-recovery",
        json={
            "identifier": "reason01@example.com",
            "reason": "Lost my phone with my authenticator app on it.",
        },
    )

    assert response.status_code == 200
    with app.app_context():
        request_record = db.session.execute(
            db.select(ManualRecoveryRequest).where(ManualRecoveryRequest.user_id == user_id)
        ).scalar_one()
        assert request_record.reason == "Lost my phone with my authenticator app on it."

        audit_row = db.session.execute(
            db.select(SecurityAuditEvent).where(SecurityAuditEvent.event_type == "manual_recovery_requested")
        ).scalar_one()
        serialized_metadata = str(audit_row.event_metadata)
        assert "Lost my phone" not in serialized_metadata
        assert audit_row.event_metadata["reason_present"] is True
        assert audit_row.event_metadata["reason_length"] == len(
            "Lost my phone with my authenticator app on it."
        )


def test_manual_recovery_request_reason_is_optional(app, client):
    response = client.post("/auth/account-recovery", json={"identifier": "no-reason@example.com"})

    assert response.status_code == 200
    with app.app_context():
        request_record = db.session.execute(db.select(ManualRecoveryRequest)).scalar_one()
        assert request_record.reason is None

        audit_row = db.session.execute(
            db.select(SecurityAuditEvent).where(SecurityAuditEvent.event_type == "manual_recovery_requested")
        ).scalar_one()
        assert audit_row.event_metadata["reason_present"] is False
        assert audit_row.event_metadata["reason_length"] == 0


def test_manual_recovery_request_generic_response_unaffected_by_reason(app, client):
    with app.app_context():
        _create_user("reason02", "reason02@example.com")

    known = client.post(
        "/auth/account-recovery",
        json={"identifier": "reason02@example.com", "reason": "Some detailed context here."},
    )
    unknown = client.post(
        "/auth/account-recovery",
        json={"identifier": "missing-reason@example.com", "reason": "Some detailed context here."},
    )

    assert known.status_code == 200
    assert unknown.status_code == 200
    assert known.get_json() == unknown.get_json()


def test_manual_recovery_request_creates_support_ticket_for_known_customer(app, client):
    with app.app_context():
        user = _create_user("recoveryticket01", "recoveryticket01@example.com")
        user_id = user.id

    response = client.post(
        "/auth/account-recovery",
        json={
            "identifier": "recoveryticket01@example.com",
            "reason": "Lost my phone with my authenticator app on it.",
        },
    )

    assert response.status_code == 200
    with app.app_context():
        ticket = db.session.execute(
            db.select(SupportTicket).where(SupportTicket.user_id == user_id)
        ).scalar_one()
        assert ticket.category == "account_recovery"
        assert ticket.status == "open"
        assert ticket.description == "Lost my phone with my authenticator app on it."


def test_manual_recovery_request_for_unknown_identifier_creates_no_support_ticket(app, client):
    response = client.post(
        "/auth/account-recovery",
        json={"identifier": "no-such-customer@example.com"},
    )

    assert response.status_code == 200
    with app.app_context():
        tickets = db.session.execute(db.select(SupportTicket)).scalars().all()
        assert tickets == []


def test_manual_recovery_dedupes_active_requests_and_keeps_public_response_generic(app, client):
    with app.app_context():
        user = _create_user("recover01", "recover01@example.com")
        user_id = user.id

    first = client.post("/auth/account-recovery", json={"identifier": "recover01@example.com"})
    duplicate = client.post("/auth/account-recovery", json={"identifier": "recover01@example.com"})
    missing = client.post("/auth/account-recovery", json={"identifier": "missing-recover@example.com"})

    assert first.status_code == 200
    assert duplicate.status_code == 200
    assert missing.status_code == 200
    assert first.get_json() == duplicate.get_json() == missing.get_json()
    with app.app_context():
        known_request = db.session.execute(
            db.select(ManualRecoveryRequest).where(ManualRecoveryRequest.user_id == user_id)
        ).scalar_one()
        unknown_request = db.session.execute(
            db.select(ManualRecoveryRequest).where(ManualRecoveryRequest.user_id.is_(None))
        ).scalar_one()
        assert known_request.status == "pending"
        assert known_request.request_count == 2
        assert unknown_request.status == "pending"
        assert db.session.execute(db.select(func.count(ManualRecoveryRequest.id))).scalar_one() == 2
        assert [item["subject"] for item in password_reset_outbox()] == [
            "SITBank manual recovery requested",
        ]
        assert db.session.query(SecurityAuditEvent).filter_by(
            event_type="manual_recovery_requested",
            outcome="deduped",
        ).count() == 1


def test_manual_recovery_duplicate_without_reason_clears_stale_reason(app, client):
    with app.app_context():
        user = _create_user("recover-reason-clear", "recover-reason-clear@example.com")
        user_id = user.id

    first = client.post(
        "/auth/account-recovery",
        json={
            "identifier": "recover-reason-clear@example.com",
            "reason": "Lost authenticator while overseas.",
        },
    )
    duplicate = client.post(
        "/auth/account-recovery",
        json={"identifier": "recover-reason-clear@example.com"},
    )

    assert first.status_code == 200
    assert duplicate.status_code == 200
    with app.app_context():
        request_record = db.session.execute(
            db.select(ManualRecoveryRequest).where(ManualRecoveryRequest.user_id == user_id)
        ).scalar_one()
        assert request_record.request_count == 2
        assert request_record.reason is None
        deduped_event = db.session.execute(
            db.select(SecurityAuditEvent).where(
                SecurityAuditEvent.event_type == "manual_recovery_requested",
                SecurityAuditEvent.outcome == "deduped",
            )
        ).scalar_one()
        assert deduped_event.event_metadata["reason_present"] is False
        assert deduped_event.event_metadata["reason_length"] == 0


def test_manual_recovery_expiry_blocks_stale_transitions(app, client):
    with app.app_context():
        user = _create_user("recover02", "recover02@example.com")
        user_id = user.id

    client.post("/auth/account-recovery", json={"identifier": "recover02@example.com"})

    with app.app_context():
        request_record = db.session.execute(
            db.select(ManualRecoveryRequest).where(ManualRecoveryRequest.user_id == user_id)
        ).scalar_one()
        request_id = request_record.id
        request_record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.session.commit()

        with pytest.raises(AuthError, match="expired"):
            transition_manual_recovery_request(request_id, "under_review")

        db.session.refresh(request_record)
        assert request_record.status == "expired"
        assert db.session.query(SecurityAuditEvent).filter_by(
            event_type="manual_recovery_expired",
            outcome="expired",
        ).count() == 1


def test_manual_recovery_valid_and_invalid_status_transitions_are_audited(app, client):
    with app.app_context():
        user = _create_user("recover03", "recover03@example.com")
        user_id = user.id

    client.post("/auth/account-recovery", json={"identifier": "recover03@example.com"})

    with app.app_context():
        request_record = db.session.execute(
            db.select(ManualRecoveryRequest).where(ManualRecoveryRequest.user_id == user_id)
        ).scalar_one()
        request_id = request_record.id

        under_review = transition_manual_recovery_request(request_id, "under_review", reason="support_triage")
        approved = transition_manual_recovery_request(request_id, "approved", reason="identity_verified")
        with pytest.raises(AuthError, match="Invalid manual recovery status transition"):
            transition_manual_recovery_request(request_id, "pending")

        db.session.refresh(request_record)
        assert under_review["status"] == "under_review"
        assert approved["status"] == "approved"
        assert request_record.status == "approved"
        assert db.session.query(SecurityAuditEvent).filter_by(
            event_type="manual_recovery_status_changed",
            outcome="success",
        ).count() == 2
        assert db.session.query(SecurityAuditEvent).filter_by(
            event_type="manual_recovery_status_changed",
            outcome="failure",
        ).count() == 1


def test_manual_recovery_completion_forces_mfa_reenrollment_and_notifies(app, client):
    with app.app_context():
        user, _secret = _create_totp_user("recover04", "recover04@example.com")
        user_id = user.id

    client.post("/auth/account-recovery", json={"identifier": "recover04@example.com"})

    with app.app_context():
        request_record = db.session.execute(
            db.select(ManualRecoveryRequest).where(ManualRecoveryRequest.user_id == user_id)
        ).scalar_one()
        request_id = request_record.id
        transition_manual_recovery_request(request_id, "under_review")
        transition_manual_recovery_request(request_id, "approved")

    with app.test_request_context("/support/manual-recovery/complete", method="POST"):
        result = complete_manual_recovery_request(request_id, reason="identity_verified")

    login = client.post("/auth/login", json={"identifier": "recover04", "password": VALID_PASSWORD})

    assert result["status"] == "completed"
    assert result["mfa_reenrollment_required"] is True
    assert login.status_code == 200
    assert login.get_json()["mfa_setup_required"] is True
    with app.app_context():
        user = db.session.get(User, user_id)
        request_record = db.session.get(ManualRecoveryRequest, request_id)
        assert user is not None
        assert request_record is not None
        assert user.mfa_enabled is False
        assert user.mfa_secret_nonce is None
        assert user.mfa_secret_ciphertext is None
        assert request_record.status == "completed"
        assert request_record.completed_at is not None
        subjects = [item["subject"] for item in password_reset_outbox()]
        assert "SITBank manual recovery requested" in subjects
        assert "SITBank manual recovery completed" in subjects
        assert db.session.query(SecurityAuditEvent).filter_by(
            event_type="manual_recovery_completed",
            outcome="success",
        ).count() == 1


def test_manual_recovery_cleanup_helper_expires_stale_active_requests(app, client):
    with app.app_context():
        user = _create_user("recover05", "recover05@example.com")
        user_id = user.id

    client.post("/auth/account-recovery", json={"identifier": "recover05@example.com"})

    with app.app_context():
        request_record = db.session.execute(
            db.select(ManualRecoveryRequest).where(ManualRecoveryRequest.user_id == user_id)
        ).scalar_one()
        request_record.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.session.commit()

        expired_count = expire_manual_recovery_requests()

        db.session.refresh(request_record)
        assert expired_count == 1
        assert request_record.status == "expired"


def test_recovery_codes_are_hashed_single_use_reset_factors(app, client):
    with app.app_context():
        user, _secret = _create_totp_user("reset07", "reset07@example.com")
        with app.test_request_context("/"):
            codes = generate_recovery_codes_for_user(user, count=2)
        stored_codes = list(db.session.execute(db.select(RecoveryCode)).scalars())
        assert len(stored_codes) == 2
        assert all(item.code_hmac not in codes for item in stored_codes)

    _request_reset(client, "reset07@example.com")
    token = _reset_token(app)
    assert _exchange(client, token).status_code == 200
    assert client.post(
        "/auth/password-reset/mfa/method",
        json={"method": "recovery_code"},
    ).status_code == 200
    verified = client.post(
        "/auth/password-reset/mfa/recovery-code",
        json={"recovery_code": codes[0]},
    )
    reused = client.post(
        "/auth/password-reset/mfa/recovery-code",
        json={"recovery_code": codes[0]},
    )

    assert verified.status_code == 200
    assert verified.get_json()["recovery_code_verified"] is True
    assert reused.status_code == 401
    with app.app_context():
        used_count = db.session.execute(
            db.select(func.count(RecoveryCode.id)).where(RecoveryCode.used_at.is_not(None))
        ).scalar_one()
        assert used_count == 1
        audit_text = json.dumps(
            [
                {
                    "event_type": event.event_type,
                    "metadata": event.event_metadata,
                }
                for event in db.session.execute(db.select(SecurityAuditEvent)).scalars()
            ],
            sort_keys=True,
        )
        assert codes[0] not in audit_text


def test_recovery_code_hmac_is_bound_to_user_and_purpose(app):
    from app.auth.recovery_codes import _recovery_code_hmac

    with app.app_context():
        first = _create_user("boundcode1", "boundcode1@example.com")
        second = _create_user(
            "boundcode2",
            "boundcode2@example.com",
            phone_number="91234568",
        )
        code = "fake-recovery-code"

        first_digest = _recovery_code_hmac(first.id, "totp_recovery", code)
        second_digest = _recovery_code_hmac(second.id, "totp_recovery", code)
        other_purpose_digest = _recovery_code_hmac(first.id, "password_reset", code)

    assert len({first_digest, second_digest, other_purpose_digest}) == 3


def test_legacy_recovery_code_hmac_rows_are_not_consumable_or_advertised(app, client):
    with app.app_context():
        user, _secret = _create_totp_user("legacyreset", "legacyreset@example.com")
        legacy_code = "legacy-code-0001"
        legacy_digest = active_hmac_hex(
            f"recovery-code:{''.join(char for char in legacy_code.casefold() if char.isalnum())}",
            length=64,
        )
        db.session.add(
            RecoveryCode(
                user_id=user.id,
                code_hmac=legacy_digest,
                hmac_version=1,
                purpose="totp_recovery",
            )
        )
        db.session.commit()

    _request_reset(client, "legacyreset@example.com")
    exchanged = _exchange(client, _reset_token(app))

    with app.app_context():
        user = db.session.execute(db.select(User).where(User.username == "legacyreset")).scalar_one()
        assert unused_recovery_code_count(user) == 0
        assert consume_recovery_code(user, legacy_code) is False

    assert exchanged.status_code == 200
    assert exchanged.get_json()["available_mfa_methods"] == ["totp"]


def test_web_reset_landing_get_is_scanner_safe_and_post_requires_csrf(app, client):
    with app.app_context():
        _create_user("scannerreset", "scannerreset@example.com")
    _request_reset(client, "scannerreset@example.com")
    token = _reset_token(app)

    first_get = client.get(f"/reset-password?token={token}")
    second_get = client.get(f"/reset-password?token={token}")
    with app.app_context():
        token_record = db.session.execute(db.select(PasswordResetToken)).scalar_one()
        assert token_record.exchanged_at is None
        assert token_record.used_at is None

    app.config["WTF_CSRF_ENABLED"] = True
    missing_csrf = client.post("/reset-password", data={"token": token})
    csrf_token = client.get("/auth/csrf-token").get_json()["csrf_token"]
    exchanged = client.post(
        "/reset-password",
        data={"token": token, "csrf_token": csrf_token},
    )

    assert first_get.status_code == 200
    assert second_get.status_code == 200
    assert token in first_get.get_data(as_text=True)
    assert missing_csrf.status_code == 400
    assert exchanged.status_code == 302
    assert exchanged.headers["Location"].endswith("/reset-password/continue")


def test_password_reset_recovery_code_requires_explicit_method_selection(app, client):
    with app.app_context():
        user, _secret = _create_totp_user("reset08", "reset08@example.com")
        with app.test_request_context("/"):
            codes = generate_recovery_codes_for_user(user, count=1)

    _request_reset(client, "reset08@example.com")
    token = _reset_token(app)
    assert _exchange(client, token).status_code == 200

    rejected = client.post(
        "/auth/password-reset/mfa/recovery-code",
        json={"recovery_code": codes[0]},
    )
    selected = client.post(
        "/auth/password-reset/mfa/method",
        json={"method": "recovery_code"},
    )
    response = client.post(
        "/auth/password-reset/mfa/recovery-code",
        json={"recovery_code": codes[0]},
    )

    assert rejected.status_code == 400
    assert selected.status_code == 200
    assert response.status_code == 200
    with app.app_context():
        assert db.session.execute(
            db.select(func.count(RecoveryCode.id)).where(RecoveryCode.used_at.is_not(None))
        ).scalar_one() == 1
