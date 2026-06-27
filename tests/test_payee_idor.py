from __future__ import annotations

from unittest.mock import Mock

import pytest

from _auth_flow_helpers import enable_mfa_for_user, login, mark_recent_mfa, register
from app.extensions import db
from app.models import Payee, SecurityAuditEvent, User


@pytest.fixture()
def payee_idor_context(app, client):
    bob_client = app.test_client()

    register(
        client,
        username="alice01",
        email="alice@sit.singaporetech.edu.sg",
        full_name="Alice Customer",
        phone_number="91234567",
    )
    register(
        bob_client,
        username="bob02",
        email="bob@sit.singaporetech.edu.sg",
        full_name="Bob Customer",
        phone_number="81234567",
    )

    alice = db.session.execute(
        db.select(User).where(User.username == "alice01")
    ).scalar_one()
    bob = db.session.execute(
        db.select(User).where(User.username == "bob02")
    ).scalar_one()
    alice.account_number = "012345678"
    bob.account_number = "012555999"
    alice.account_type = bob.account_type = "customer"
    alice.account_status = bob.account_status = "active"

    bob_payee = Payee(
        user_id=bob.id,
        nickname="Bob Private Payee",
        account_number="987654321",
        recipient_name="Private Recipient",
    )
    db.session.add(bob_payee)
    db.session.commit()

    login(client, identifier=alice.username)
    alice, _secret = enable_mfa_for_user(alice.username)
    mark_recent_mfa(client, alice)

    assert alice.account_type == bob.account_type == "customer"
    assert alice.account_status == bob.account_status == "active"

    return {
        "alice": alice,
        "bob": bob,
        "bob_payee_id": bob_payee.id,
        "bob_payee_details": (
            bob_payee.nickname,
            bob_payee.account_number,
            bob_payee.recipient_name,
        ),
    }


def test_user_cannot_view_other_users_payee_remove_page(
    client, payee_idor_context
):
    payee_id = payee_idor_context["bob_payee_id"]

    response = client.get(f"/banking/payees/{payee_id}/remove")

    assert response.status_code == 404
    for private_value in payee_idor_context["bob_payee_details"]:
        assert private_value.encode() not in response.data


def test_user_cannot_remove_other_users_payee(client, payee_idor_context):
    alice = payee_idor_context["alice"]
    payee_id = payee_idor_context["bob_payee_id"]

    response = client.post(
        f"/banking/payees/{payee_id}/remove",
        data={"totp_code": "000000"},
    )

    assert response.status_code == 404
    assert db.session.get(Payee, payee_id) is not None
    successful_remove_events = db.session.execute(
        db.select(SecurityAuditEvent).where(
            SecurityAuditEvent.event_type == "payee_remove",
            SecurityAuditEvent.outcome == "success",
            SecurityAuditEvent.user_id == alice.id,
        )
    ).scalars()
    assert list(successful_remove_events) == []


def test_payee_list_only_shows_current_users_payees(client, payee_idor_context):
    alice = payee_idor_context["alice"]
    alice_payee = Payee(
        user_id=alice.id,
        nickname="Alice Visible Payee",
        account_number="123456789",
        recipient_name="Visible Recipient",
    )
    db.session.add(alice_payee)
    db.session.commit()

    response = client.get("/banking/payees")

    assert response.status_code == 200
    assert alice_payee.nickname.encode() in response.data
    assert f"•••-•••-{alice_payee.account_number[-3:]}".encode() in response.data
    assert alice_payee.recipient_name.encode() in response.data
    for private_value in payee_idor_context["bob_payee_details"]:
        assert private_value.encode() not in response.data
    bob_account = payee_idor_context["bob_payee_details"][1]
    assert f"•••-•••-{bob_account[-3:]}".encode() not in response.data


def test_cross_user_payee_remove_fails_before_mfa_processing(
    client, payee_idor_context, monkeypatch
):
    from app.banking import routes as banking_routes

    payee_id = payee_idor_context["bob_payee_id"]
    verify_authorization = Mock(
        side_effect=AssertionError("cross-user request reached MFA processing")
    )
    monkeypatch.setattr(
        banking_routes,
        "verify_high_risk_authorization",
        verify_authorization,
    )

    response = client.post(
        f"/banking/payees/{payee_id}/remove",
        data={"totp_code": "000000"},
    )

    assert response.status_code == 404
    verify_authorization.assert_not_called()
    assert db.session.get(Payee, payee_id) is not None
