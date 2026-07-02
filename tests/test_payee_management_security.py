from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pyotp

from _auth_flow_helpers import (
    add_security_keys_for_user,
    enable_mfa_for_user,
    login,
    mark_recent_mfa,
    register,
)
from app.extensions import db
from app.models import Payee, SecurityAuditEvent, User
from app.security.rate_limits import clear_failures


def _user(username: str) -> User:
    return db.session.execute(db.select(User).where(User.username == username)).scalar_one()


def _set_account(username: str, account_number: str) -> User:
    user = _user(username)
    user.account_number = account_number
    db.session.commit()
    return user


def _freeze_totp_verifier(monkeypatch) -> int:
    timestamp = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: timestamp)
    return timestamp


def _current_totp(secret: str, timestamp: int | None = None) -> str:
    if timestamp is None:
        timestamp = int(time.time())
    return pyotp.TOTP(secret, digits=6, interval=30).at(timestamp)


def _register_customer(client, *, username: str, email: str, phone: str, account: str) -> User:
    register(
        client,
        username=username,
        email=email,
        full_name=f"{''.join(c for c in username if c.isalpha()).title()} Test",
        phone_number=phone,
    )
    return _set_account(username, account)


def _login_mfa_customer(client, *, username: str = "alice01") -> tuple[User, str]:
    login(client, identifier=username)
    user, secret = enable_mfa_for_user(username)
    mark_recent_mfa(client, user)
    return user, secret


def test_banking_routes_require_totp_mfa_on_direct_access(client):
    register(client)
    login(client)

    payees_response = client.get("/banking/payees")
    add_response = client.get("/banking/payees/add")

    assert payees_response.status_code == 302
    assert payees_response.headers["Location"].endswith("/mfa/setup")
    assert add_response.status_code == 302
    assert add_response.headers["Location"].endswith("/mfa/setup")


def test_legacy_passkey_only_user_cannot_access_banking_routes(client):
    register(client)
    login(client)
    user = _user("alice01")
    add_security_keys_for_user(user)

    response = client.get("/banking/payees")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/mfa/setup")


def test_totp_user_can_access_banking_routes(client):
    register(client)
    _login_mfa_customer(client)

    response = client.get("/banking/payees")

    assert response.status_code == 200


def test_payee_lookup_does_not_reveal_recipient_before_totp(app, client):
    bob_client = app.test_client()
    _register_customer(
        client,
        username="alice01",
        email="alice@example.com",
        phone="91234567",
        account="012345678",
    )
    bob = _register_customer(
        bob_client,
        username="bob02",
        email="bob@example.com",
        phone="81234567",
        account="012555999",
    )
    _login_mfa_customer(client)

    response = client.post(
        "/banking/payees/add",
        data={
            "nickname": "Bob",
            "account_number": bob.account_number,
            "totp_code": "000000",
        },
    )

    assert response.status_code == 401
    assert bob.full_name.encode("utf-8") not in response.data
    with client.session_transaction() as sess:
        assert "pending_payee" not in sess


def test_payee_lookup_requires_totp_before_confirmation(app, client, monkeypatch):
    bob_client = app.test_client()
    _register_customer(
        client,
        username="alice01",
        email="alice@example.com",
        phone="91234567",
        account="012345678",
    )
    bob = _register_customer(
        bob_client,
        username="bob02",
        email="bob@example.com",
        phone="81234567",
        account="012555999",
    )
    _alice, secret = _login_mfa_customer(client)
    totp_time = _freeze_totp_verifier(monkeypatch)

    lookup = client.post(
        "/banking/payees/add",
        data={
            "nickname": "Bob",
            "account_number": bob.account_number,
            "totp_code": _current_totp(secret, totp_time),
        },
    )
    confirm = client.get("/banking/payees/confirm")
    save = client.post("/banking/payees/confirm")

    assert lookup.status_code == 302
    assert lookup.headers["Location"].endswith("/banking/payees/confirm")
    assert confirm.status_code == 200
    assert bob.full_name.encode("utf-8") in confirm.data
    assert save.status_code == 302
    payee = db.session.execute(db.select(Payee).where(Payee.user_id == _user("alice01").id)).scalar_one()
    assert payee.account_number == bob.account_number
    assert payee.recipient_name == bob.full_name


def test_payee_add_rejects_passkey_stepup_token(app, client):
    bob_client = app.test_client()
    _register_customer(
        client,
        username="alice01",
        email="alice@example.com",
        phone="91234567",
        account="012345678",
    )
    bob = _register_customer(
        bob_client,
        username="bob02",
        email="bob@example.com",
        phone="81234567",
        account="012555999",
    )
    _alice, secret = _login_mfa_customer(client)

    response = client.post(
        "/banking/payees/add",
        data={
            "nickname": "Bob",
            "account_number": bob.account_number,
            "totp_code": _current_totp(secret),
            "stepup_token": "A" * 40,
        },
    )

    assert response.status_code == 403
    assert b"authenticator code" in response.data
    with client.session_transaction() as sess:
        assert "pending_payee" not in sess


def test_invalid_payee_lookup_is_generic_and_audited(client, monkeypatch):
    _register_customer(
        client,
        username="alice01",
        email="alice@example.com",
        phone="91234567",
        account="012345678",
    )
    _alice, secret = _login_mfa_customer(client)
    totp_time = _freeze_totp_verifier(monkeypatch)

    response = client.post(
        "/banking/payees/add",
        data={
            "nickname": "Missing",
            "account_number": "012000999",
            "totp_code": _current_totp(secret, totp_time),
        },
    )
    event = db.session.query(SecurityAuditEvent).filter_by(event_type="payee_lookup", outcome="failure").one()

    assert response.status_code == 400
    assert b"Could not add that payee" in response.data
    assert "account_ref" in event.event_metadata
    assert "012000999" not in str(event.event_metadata)


def test_payee_add_and_remove_audit_metadata_uses_safe_references(app, client, monkeypatch):
    bob_client = app.test_client()
    _register_customer(
        client,
        username="alice01",
        email="alice@example.com",
        phone="91234567",
        account="012345678",
    )
    bob = _register_customer(
        bob_client,
        username="bob02",
        email="bob@example.com",
        phone="81234567",
        account="012555999",
    )
    _alice, secret = _login_mfa_customer(client)
    totp_time = _freeze_totp_verifier(monkeypatch)

    nickname = "Sensitive Bob Alias"
    lookup = client.post(
        "/banking/payees/add",
        data={
            "nickname": nickname,
            "account_number": bob.account_number,
            "totp_code": _current_totp(secret, totp_time),
        },
    )
    confirm = client.post("/banking/payees/confirm")
    payee = db.session.execute(db.select(Payee).where(Payee.account_number == bob.account_number)).scalar_one()
    clear_failures("payee_remove", str(_alice.id))
    removed = client.post(
        f"/banking/payees/{payee.id}/remove",
        data={"totp_code": _current_totp(secret, totp_time)},
    )

    add_event = db.session.query(SecurityAuditEvent).filter_by(event_type="payee_add", outcome="success").one()
    remove_event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="payee_remove",
        outcome="success",
    ).one()
    combined_metadata = f"{add_event.event_metadata} {remove_event.event_metadata}"

    assert lookup.status_code == 302
    assert confirm.status_code == 302
    assert removed.status_code == 302
    assert "payee_account_ref" in add_event.event_metadata
    assert "payee_account_ref" in remove_event.event_metadata
    assert remove_event.event_metadata["nickname_present"] is True
    assert remove_event.event_metadata["nickname_length"] == len(nickname)
    assert bob.account_number not in combined_metadata
    assert nickname not in combined_metadata
    assert "account_number" not in add_event.event_metadata
    assert "account_number" not in remove_event.event_metadata
    assert "nickname" not in remove_event.event_metadata


def test_self_and_duplicate_payee_are_rejected_before_pending_state(app, client, monkeypatch):
    bob_client = app.test_client()
    alice = _register_customer(
        client,
        username="alice01",
        email="alice@example.com",
        phone="91234567",
        account="012345678",
    )
    bob = _register_customer(
        bob_client,
        username="bob02",
        email="bob@example.com",
        phone="81234567",
        account="012555999",
    )
    db.session.add(Payee(user_id=alice.id, nickname="Existing", account_number=bob.account_number, recipient_name=bob.full_name))
    db.session.commit()
    _alice, secret = _login_mfa_customer(client)
    totp_time = _freeze_totp_verifier(monkeypatch)

    self_response = client.post(
        "/banking/payees/add",
        data={
            "nickname": "Me",
            "account_number": alice.account_number,
            "totp_code": _current_totp(secret, totp_time),
        },
    )
    duplicate_response = client.post(
        "/banking/payees/add",
        data={
            "nickname": "Bob",
            "account_number": bob.account_number,
            "totp_code": _current_totp(secret, totp_time),
        },
    )

    assert self_response.status_code == 400
    assert duplicate_response.status_code == 400
    with client.session_transaction() as sess:
        assert "pending_payee" not in sess


def test_pending_payee_confirmation_expires(app, client):
    bob_client = app.test_client()
    _register_customer(
        client,
        username="alice01",
        email="alice@example.com",
        phone="91234567",
        account="012345678",
    )
    bob = _register_customer(
        bob_client,
        username="bob02",
        email="bob@example.com",
        phone="81234567",
        account="012555999",
    )
    _login_mfa_customer(client)
    with client.session_transaction() as sess:
        sess["pending_payee"] = {
            "nickname": "Bob",
            "account_number": bob.account_number,
            "recipient_name": bob.full_name,
            "authorization_action": "payee_add",
            "authorized_at": (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(),
            "expires_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
        }

    response = client.post("/banking/payees/confirm")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/banking/payees/add")
    assert db.session.query(Payee).count() == 0


def test_payee_removal_enforces_ownership_and_totp(app, client):
    bob_client = app.test_client()
    alice = _register_customer(
        client,
        username="alice01",
        email="alice@example.com",
        phone="91234567",
        account="012345678",
    )
    bob = _register_customer(
        bob_client,
        username="bob02",
        email="bob@example.com",
        phone="81234567",
        account="012555999",
    )
    payee = Payee(user_id=bob.id, nickname="Alice", account_number=alice.account_number, recipient_name=alice.full_name)
    db.session.add(payee)
    db.session.commit()
    _alice, secret = _login_mfa_customer(client)

    get_response = client.get(f"/banking/payees/{payee.id}/remove")
    post_response = client.post(
        f"/banking/payees/{payee.id}/remove",
        data={"totp_code": _current_totp(secret)},
    )

    assert get_response.status_code == 404
    assert post_response.status_code == 404
    assert db.session.get(Payee, payee.id) is not None


def test_payee_routes_cover_missing_expired_and_unauthorized_pending_state(client):
    alice = _register_customer(
        client,
        username="alice01",
        email="alice@example.com",
        phone="91234567",
        account="012345678",
    )
    _login_mfa_customer(client)

    add_page = client.get("/banking/payees/add")
    invalid_add = client.post("/banking/payees/add", data={})
    missing_get = client.get("/banking/payees/confirm")
    missing_post = client.post("/banking/payees/confirm")

    with client.session_transaction() as session_state:
        session_state["pending_payee"] = {
            "nickname": "Expired",
            "account_number": "012000999",
            "authorization_action": "payee_add",
            "authorized_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
        }
    expired = client.get("/banking/payees/confirm")

    with client.session_transaction() as session_state:
        session_state["pending_payee"] = {
            "nickname": "Unauthorized",
            "account_number": "012000999",
            "authorization_action": "other",
            "authorized_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        }
    unauthorized = client.post("/banking/payees/confirm")

    with client.session_transaction() as session_state:
        session_state["pending_payee"] = {
            "nickname": "Self",
            "account_number": alice.account_number,
            "authorization_action": "payee_add",
            "authorized_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        }
    self_payee = client.post("/banking/payees/confirm")

    assert add_page.status_code == 200
    assert invalid_add.status_code == 400
    assert missing_get.status_code == 302
    assert missing_post.status_code == 302
    assert expired.status_code == 302
    assert unauthorized.status_code == 302
    assert self_payee.status_code == 302


def test_payee_confirmation_handles_missing_duplicate_and_removal_paths(
    app,
    client,
    monkeypatch,
):
    from app.banking import routes as banking_routes

    bob_client = app.test_client()
    alice = _register_customer(
        client,
        username="alice01",
        email="alice@example.com",
        phone="91234567",
        account="012345678",
    )
    bob = _register_customer(
        bob_client,
        username="bob02",
        email="bob@example.com",
        phone="81234567",
        account="012555999",
    )
    _alice, secret = _login_mfa_customer(client)
    totp_time = _freeze_totp_verifier(monkeypatch)

    def pending(account_number: str, nickname: str = "Payee") -> dict[str, str]:
        return {
            "nickname": nickname,
            "account_number": account_number,
            "authorization_action": "payee_add",
            "authorized_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        }

    with client.session_transaction() as session_state:
        session_state["pending_payee"] = pending("012000999", "Missing")
    missing = client.post("/banking/payees/confirm")

    existing = Payee(
        user_id=alice.id,
        nickname="Existing",
        account_number=bob.account_number,
        recipient_name=bob.full_name,
    )
    db.session.add(existing)
    db.session.commit()
    with client.session_transaction() as session_state:
        session_state["pending_payee"] = pending(bob.account_number, "Duplicate")
    duplicate = client.post("/banking/payees/confirm")

    remove_page = client.get(f"/banking/payees/{existing.id}/remove")
    real_remove_form = banking_routes.MfaOrStepUpForm
    real_render_template = banking_routes.render_template
    monkeypatch.setattr(
        banking_routes,
        "MfaOrStepUpForm",
        lambda: type("InvalidForm", (), {"validate_on_submit": lambda self: False})(),
    )
    monkeypatch.setattr(
        banking_routes,
        "render_template",
        lambda *_args, **_kwargs: "invalid form",
    )
    invalid_remove = client.post(f"/banking/payees/{existing.id}/remove", data={})
    monkeypatch.setattr(banking_routes, "MfaOrStepUpForm", real_remove_form)
    monkeypatch.setattr(banking_routes, "render_template", real_render_template)
    denied_remove = client.post(
        f"/banking/payees/{existing.id}/remove",
        data={"totp_code": "000000"},
    )
    clear_failures("payee_remove", str(alice.id))
    successful_remove = client.post(
        f"/banking/payees/{existing.id}/remove",
        data={"totp_code": _current_totp(secret, totp_time)},
    )

    assert missing.status_code == 302
    assert duplicate.status_code == 302
    assert remove_page.status_code == 200
    assert invalid_remove.status_code == 400
    assert denied_remove.status_code == 401
    assert successful_remove.status_code == 302
    assert db.session.get(Payee, existing.id) is None
