from __future__ import annotations

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


def _user(username: str) -> User:
    return db.session.execute(db.select(User).where(User.username == username)).scalar_one()


def _set_account(username: str, account_number: str) -> User:
    user = _user(username)
    user.account_number = account_number
    db.session.commit()
    return user


def _current_totp(secret: str) -> str:
    return pyotp.TOTP(secret, digits=6, interval=30).now()


def _register_customer(client, *, username: str, email: str, phone: str, account: str) -> User:
    register(
        client,
        username=username,
        email=email,
        full_name=f"{username.title()} Test",
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
        email="alice@sit.singaporetech.edu.sg",
        phone="91234567",
        account="012345678",
    )
    bob = _register_customer(
        bob_client,
        username="bob02",
        email="bob@sit.singaporetech.edu.sg",
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


def test_payee_lookup_requires_totp_before_confirmation(app, client):
    bob_client = app.test_client()
    _register_customer(
        client,
        username="alice01",
        email="alice@sit.singaporetech.edu.sg",
        phone="91234567",
        account="012345678",
    )
    bob = _register_customer(
        bob_client,
        username="bob02",
        email="bob@sit.singaporetech.edu.sg",
        phone="81234567",
        account="012555999",
    )
    _alice, secret = _login_mfa_customer(client)

    lookup = client.post(
        "/banking/payees/add",
        data={
            "nickname": "Bob",
            "account_number": bob.account_number,
            "totp_code": _current_totp(secret),
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
        email="alice@sit.singaporetech.edu.sg",
        phone="91234567",
        account="012345678",
    )
    bob = _register_customer(
        bob_client,
        username="bob02",
        email="bob@sit.singaporetech.edu.sg",
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


def test_invalid_payee_lookup_is_generic_and_audited(client):
    _register_customer(
        client,
        username="alice01",
        email="alice@sit.singaporetech.edu.sg",
        phone="91234567",
        account="012345678",
    )
    _alice, secret = _login_mfa_customer(client)

    response = client.post(
        "/banking/payees/add",
        data={
            "nickname": "Missing",
            "account_number": "012000999",
            "totp_code": _current_totp(secret),
        },
    )
    event = db.session.query(SecurityAuditEvent).filter_by(event_type="payee_lookup", outcome="failure").one()

    assert response.status_code == 400
    assert b"Could not add that payee" in response.data
    assert "account_ref" in event.event_metadata
    assert "012000999" not in str(event.event_metadata)


def test_self_and_duplicate_payee_are_rejected_before_pending_state(app, client):
    bob_client = app.test_client()
    alice = _register_customer(
        client,
        username="alice01",
        email="alice@sit.singaporetech.edu.sg",
        phone="91234567",
        account="012345678",
    )
    bob = _register_customer(
        bob_client,
        username="bob02",
        email="bob@sit.singaporetech.edu.sg",
        phone="81234567",
        account="012555999",
    )
    db.session.add(Payee(user_id=alice.id, nickname="Existing", account_number=bob.account_number, recipient_name=bob.full_name))
    db.session.commit()
    _alice, secret = _login_mfa_customer(client)

    self_response = client.post(
        "/banking/payees/add",
        data={"nickname": "Me", "account_number": alice.account_number, "totp_code": _current_totp(secret)},
    )
    duplicate_response = client.post(
        "/banking/payees/add",
        data={"nickname": "Bob", "account_number": bob.account_number, "totp_code": _current_totp(secret)},
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
        email="alice@sit.singaporetech.edu.sg",
        phone="91234567",
        account="012345678",
    )
    bob = _register_customer(
        bob_client,
        username="bob02",
        email="bob@sit.singaporetech.edu.sg",
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
        email="alice@sit.singaporetech.edu.sg",
        phone="91234567",
        account="012345678",
    )
    bob = _register_customer(
        bob_client,
        username="bob02",
        email="bob@sit.singaporetech.edu.sg",
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
