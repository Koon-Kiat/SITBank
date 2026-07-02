from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timezone

import pytest
from flask import request

from app.extensions import db
from app.models import SecurityAuditEvent, ServerSideSession, User
from app.security import sessions as sessions_module
from app.security.session_hmac import (
    SESSION_PAYLOAD_FORMAT_VERSION,
    SessionPayloadIntegrityError,
    sign_session_payload,
    verify_session_payload,
)
from app.security.sessions import session_lookup_hash


def _create_user(username: str = "alice01", full_name: str = "Alice Test", phone_number: str = "91234567") -> int:
    account_number = "012" + "".join(str(secrets.randbelow(10)) for _ in range(6))
    user = User(
        username=username,
        email=f"{username}@example.com",
        password_hash="not-used-by-session-integrity-tests",
        mfa_enabled=True,
        full_name=full_name,
        phone_number=phone_number,
        account_number=account_number,
    )
    db.session.add(user)
    db.session.commit()
    return user.id


def _authenticate_session(client, user_id: int) -> str:
    now = int(time.time())
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["auth_context"] = "password+mfa"
        sess["login_at"] = datetime.now(timezone.utc).isoformat()
        sess["last_activity_at"] = now
        sess["mfa_verified_at"] = now
        sess["fresh_mfa_verified_at"] = now
        return sess.sid


def _session_record(session_id: str) -> ServerSideSession:
    record = db.session.execute(
        db.select(ServerSideSession).where(
            ServerSideSession.session_lookup_hash == session_lookup_hash(session_id)
        )
    ).scalar_one()
    return record


def _load_envelope(app, session_id: str) -> dict:
    del app
    raw = _session_record(session_id).payload
    assert raw is not None
    return json.loads(bytes(raw).decode("utf-8"))


def _store_envelope(app, session_id: str, envelope: dict) -> None:
    del app
    record = _session_record(session_id)
    record.payload = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8")
    db.session.commit()


def _session_payload(app, envelope: dict) -> dict:
    payload = base64.b64decode(envelope["payload"], validate=True)
    return app.session_interface.serializer.decode(payload)


def _replace_unsigned_payload(app, session_id: str, mutator) -> None:
    envelope = _load_envelope(app, session_id)
    payload = _session_payload(app, envelope)
    mutator(payload)
    envelope["payload"] = base64.b64encode(
        app.session_interface.serializer.encode(payload)
    ).decode("ascii")
    _store_envelope(app, session_id, envelope)


def _signature(app, key_id: str, encoded_payload: str, binding_context: str) -> str:
    signing_input = json.dumps(
        {
            "ctx": binding_context,
            "kid": key_id,
            "payload": encoded_payload,
            "v": SESSION_PAYLOAD_FORMAT_VERSION,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return hmac.new(
        app.config["SESSION_HMAC_KEYS"][key_id],
        signing_input.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _assert_session_rejected(app, client) -> None:
    response = client.get("/dashboard")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")
    assert (
        db.session.query(SecurityAuditEvent)
        .filter_by(event_type="session_integrity", outcome="failure")
        .count()
        == 1
    )


def test_valid_db_session_payload_continues_to_authenticate(app, client):
    user_id = _create_user()
    session_id = _authenticate_session(client, user_id)

    envelope = _load_envelope(app, session_id)
    response = client.get("/dashboard")

    assert envelope["v"] == SESSION_PAYLOAD_FORMAT_VERSION
    assert envelope["kid"] == "test-current"
    assert envelope["sig"]
    assert response.status_code == 200
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="session_integrity").count() == 0


def test_session_row_missing_expiry_is_rejected_without_server_error(app, monkeypatch, caplog):
    session_id = "malformed-session-id"
    record = ServerSideSession(
        component="customer",
        session_lookup_hash=session_lookup_hash(session_id),
        created_at=datetime.now(timezone.utc),
        last_activity_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc),
    )
    record.expires_at = None

    monkeypatch.setattr(
        sessions_module,
        "_session_record_for_sid",
        lambda _session_id: record,
    )
    caplog.set_level("WARNING", logger=app.logger.name)

    with app.test_request_context(
        "/static/img/sitbank-mark.svg",
        headers={"Cookie": f"{app.config['SESSION_COOKIE_NAME']}={session_id}"},
    ):
        loaded = app.session_interface.open_session(app, request)

    assert loaded.new is True
    assert loaded.sid != session_id
    assert record.ended_reason == "integrity_failure"
    assert record.revoked_at is not None
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="session_integrity",
        outcome="failure",
    ).count() == 1
    assert "missing_expires_at" in "\n".join(record.getMessage() for record in caplog.records)


def test_modified_db_session_user_id_is_rejected(app, client):
    alice_id = _create_user("alice01")
    bob_id = _create_user("bob02", full_name="Bob Test", phone_number="81234567")
    session_id = _authenticate_session(client, alice_id)

    _replace_unsigned_payload(app, session_id, lambda payload: payload.update(user_id=bob_id))

    _assert_session_rejected(app, client)


def test_modified_db_session_privilege_flags_are_rejected(app, client):
    user_id = _create_user()
    session_id = _authenticate_session(client, user_id)

    def add_privileged_flags(payload: dict) -> None:
        payload["is_admin"] = True
        payload["role"] = "admin"

    _replace_unsigned_payload(app, session_id, add_privileged_flags)

    _assert_session_rejected(app, client)


def test_tampered_db_session_payload_logs_only_safe_reference(app, client, caplog):
    user_id = _create_user()
    session_id = _authenticate_session(client, user_id)
    secret_marker = "session-payload-secret-marker"

    def add_sensitive_payload(payload: dict) -> None:
        payload["is_admin"] = True
        payload["totp_secret"] = secret_marker

    _replace_unsigned_payload(app, session_id, add_sensitive_payload)

    caplog.set_level("WARNING")
    _assert_session_rejected(app, client)
    log_text = "\n".join(record.getMessage() for record in caplog.records)

    assert "session_integrity_failure" in log_text
    assert "store_ref=" in log_text
    assert session_id not in log_text
    assert secret_marker not in log_text
    assert "totp_secret" not in log_text


def test_missing_db_session_signature_is_rejected(app, client):
    user_id = _create_user()
    session_id = _authenticate_session(client, user_id)
    envelope = _load_envelope(app, session_id)
    envelope.pop("sig")
    _store_envelope(app, session_id, envelope)

    _assert_session_rejected(app, client)


def test_invalid_db_session_signature_is_rejected(app, client):
    user_id = _create_user()
    session_id = _authenticate_session(client, user_id)
    envelope = _load_envelope(app, session_id)
    envelope["sig"] = "0" * 64
    _store_envelope(app, session_id, envelope)

    _assert_session_rejected(app, client)


def test_unknown_db_session_hmac_key_id_is_rejected(app, client):
    user_id = _create_user()
    session_id = _authenticate_session(client, user_id)
    envelope = _load_envelope(app, session_id)
    envelope["kid"] = "unknown-key"
    _store_envelope(app, session_id, envelope)

    _assert_session_rejected(app, client)


def test_malformed_db_session_payload_is_rejected(app, client):
    user_id = _create_user()
    session_id = _authenticate_session(client, user_id)
    envelope = _load_envelope(app, session_id)
    envelope["payload"] = "not-valid-base64"
    envelope["sig"] = _signature(
        app,
        envelope["kid"],
        envelope["payload"],
        f"db-session:{app.config['APP_MODE']}:{session_lookup_hash(session_id)}",
    )
    _store_envelope(app, session_id, envelope)

    _assert_session_rejected(app, client)


def test_unsupported_db_session_payload_format_is_rejected(app, client):
    user_id = _create_user()
    session_id = _authenticate_session(client, user_id)
    record = _session_record(session_id)
    record.payload = b"legacy-raw-session"
    db.session.commit()

    _assert_session_rejected(app, client)


def test_signed_db_session_payload_copied_to_another_row_is_rejected(app, client):
    alice_id = _create_user("alice01")
    alice_session_id = _authenticate_session(client, alice_id)
    signed_payload = _session_record(alice_session_id).payload
    assert signed_payload is not None

    second_client = app.test_client()
    bob_id = _create_user("bob02", full_name="Bob Test", phone_number="81234567")
    bob_session_id = _authenticate_session(second_client, bob_id)
    bob_record = _session_record(bob_session_id)
    bob_record.payload = signed_payload
    db.session.commit()

    _assert_session_rejected(app, second_client)


def test_db_session_payload_survives_active_hmac_key_rotation(app, client):
    user_id = _create_user()
    session_id = _authenticate_session(client, user_id)
    assert _load_envelope(app, session_id)["kid"] == "test-current"

    app.config["SESSION_HMAC_ACTIVE_KEY_ID"] = "test-previous"
    response = client.get("/dashboard")
    rotated_envelope = _load_envelope(app, session_id)

    assert response.status_code == 200
    assert rotated_envelope["kid"] == "test-previous"


def test_session_payload_binding_context_is_required_and_checked(app):
    payload = app.session_interface.serializer.encode({"user_id": 1})
    signed_payload = sign_session_payload(payload, binding_context="session:alpha")

    assert verify_session_payload(signed_payload, binding_context="session:alpha") == payload

    with pytest.raises(SessionPayloadIntegrityError) as missing_context:
        verify_session_payload(signed_payload, binding_context="")
    assert missing_context.value.reason == "missing_binding_context"

    with pytest.raises(SessionPayloadIntegrityError) as wrong_context:
        verify_session_payload(signed_payload, binding_context="session:bravo")
    assert wrong_context.value.reason == "invalid_signature"
