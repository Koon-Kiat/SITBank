from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone

import pytest

from app.extensions import db
from app.models import SecurityAuditEvent, User
from app.security.session_hmac import (
    SESSION_PAYLOAD_FORMAT_VERSION,
    SessionPayloadIntegrityError,
    sign_session_payload,
    verify_session_payload,
)


def _create_user(username: str = "alice01") -> int:
    user = User(
        username=username,
        email=f"{username}@example.com",
        password_hash="not-used-by-session-integrity-tests",
        mfa_enabled=True,
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


def _session_key(app, session_id: str) -> str:
    return f"{app.config['SESSION_KEY_PREFIX']}{session_id}"


def _load_envelope(app, session_id: str) -> dict:
    raw = app.extensions["redis_session"].get(_session_key(app, session_id))
    assert raw is not None
    return json.loads(raw.decode("utf-8"))


def _store_envelope(app, session_id: str, envelope: dict) -> None:
    app.extensions["redis_session"].set(
        _session_key(app, session_id),
        json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8"),
    )


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


def test_valid_redis_session_payload_continues_to_authenticate(app, client):
    user_id = _create_user()
    session_id = _authenticate_session(client, user_id)

    envelope = _load_envelope(app, session_id)
    response = client.get("/dashboard")

    assert envelope["v"] == SESSION_PAYLOAD_FORMAT_VERSION
    assert envelope["kid"] == "test-current"
    assert envelope["sig"]
    assert response.status_code == 200
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="session_integrity").count() == 0


def test_modified_redis_session_user_id_is_rejected(app, client):
    alice_id = _create_user("alice01")
    bob_id = _create_user("bob02")
    session_id = _authenticate_session(client, alice_id)

    _replace_unsigned_payload(app, session_id, lambda payload: payload.update(user_id=bob_id))

    _assert_session_rejected(app, client)


def test_modified_redis_session_privilege_flags_are_rejected(app, client):
    user_id = _create_user()
    session_id = _authenticate_session(client, user_id)

    def add_privileged_flags(payload: dict) -> None:
        payload["is_admin"] = True
        payload["role"] = "admin"

    _replace_unsigned_payload(app, session_id, add_privileged_flags)

    _assert_session_rejected(app, client)


def test_missing_redis_session_signature_is_rejected(app, client):
    user_id = _create_user()
    session_id = _authenticate_session(client, user_id)
    envelope = _load_envelope(app, session_id)
    envelope.pop("sig")
    _store_envelope(app, session_id, envelope)

    _assert_session_rejected(app, client)


def test_invalid_redis_session_signature_is_rejected(app, client):
    user_id = _create_user()
    session_id = _authenticate_session(client, user_id)
    envelope = _load_envelope(app, session_id)
    envelope["sig"] = "0" * 64
    _store_envelope(app, session_id, envelope)

    _assert_session_rejected(app, client)


def test_unknown_redis_session_hmac_key_id_is_rejected(app, client):
    user_id = _create_user()
    session_id = _authenticate_session(client, user_id)
    envelope = _load_envelope(app, session_id)
    envelope["kid"] = "unknown-key"
    _store_envelope(app, session_id, envelope)

    _assert_session_rejected(app, client)


def test_malformed_redis_session_payload_is_rejected(app, client):
    user_id = _create_user()
    session_id = _authenticate_session(client, user_id)
    envelope = _load_envelope(app, session_id)
    envelope["payload"] = "not-valid-base64"
    envelope["sig"] = _signature(
        app,
        envelope["kid"],
        envelope["payload"],
        _session_key(app, session_id),
    )
    _store_envelope(app, session_id, envelope)

    _assert_session_rejected(app, client)


def test_unsupported_redis_session_payload_format_is_rejected(app, client):
    user_id = _create_user()
    session_id = _authenticate_session(client, user_id)
    app.extensions["redis_session"].set(_session_key(app, session_id), b"legacy-raw-session")

    _assert_session_rejected(app, client)


def test_signed_redis_session_payload_copied_to_another_key_is_rejected(app, client):
    alice_id = _create_user("alice01")
    alice_session_id = _authenticate_session(client, alice_id)
    signed_payload = app.extensions["redis_session"].get(_session_key(app, alice_session_id))
    assert signed_payload is not None

    second_client = app.test_client()
    bob_id = _create_user("bob02")
    bob_session_id = _authenticate_session(second_client, bob_id)
    app.extensions["redis_session"].set(_session_key(app, bob_session_id), signed_payload)

    _assert_session_rejected(app, second_client)


def test_redis_session_payload_survives_active_hmac_key_rotation(app, client):
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
