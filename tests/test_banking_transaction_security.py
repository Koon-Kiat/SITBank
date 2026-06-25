from __future__ import annotations

from _auth_flow_helpers import *


def test_future_transaction_payload_guardrails_reject_server_controlled_fields():
    from app.auth.services import AuthError
    from app.banking.services import validate_public_transaction_payload

    with pytest.raises(AuthError):
        validate_public_transaction_payload(
            {
                "idempotency_key": "11111111-1111-4111-8111-111111111111",
                "amount": "10.00",
                "account_id": "acct-1",
            }
        )
    with pytest.raises(AuthError):
        validate_public_transaction_payload({"amount": "10.00", "currency": "SGD"})
    with pytest.raises(AuthError):
        validate_public_transaction_payload(
            {
                "idempotency_key": "22222222-2222-4222-8222-222222222222",
                "amount": "10.00",
                "currency": "SGD",
                "payee": "PAYEE-001",
                "memo": "unexpected public field",
            }
        )

    normalized = validate_public_transaction_payload(
        {
            "idempotency_key": " 33333333-3333-4333-8333-333333333333 ",
            "amount": "10.00",
            "currency": "sgd",
            "payee": " payee-001 ",
        }
    )

    assert normalized["idempotency_key"] == "33333333-3333-4333-8333-333333333333"
    assert normalized["currency"] == "SGD"
    assert normalized["payee"] == "PAYEE-001"

def test_public_transaction_payload_business_rules_reject_unsafe_values():
    from app.auth.services import AuthError
    from app.banking.services import validate_public_transaction_payload

    valid = {
        "idempotency_key": "44444444-4444-4444-8444-444444444444",
        "amount": "10.00",
        "currency": "SGD",
        "payee": "PAYEE-001",
    }

    invalid_cases = [
        {**valid, "amount": "50000.01"},
        {**valid, "amount": "10.001"},
        {**valid, "amount": "0.00"},
        {**valid, "amount": "NaN"},
        {**valid, "currency": "USD"},
        {**valid, "payee": "../etc/passwd"},
        {**valid, "idempotency_key": "not-a-uuid"},
    ]

    for payload in invalid_cases:
        with pytest.raises(AuthError):
            validate_public_transaction_payload(payload)

def test_transfer_step_up_policy_distinguishes_normal_and_stronger_flows():
    from app.auth.services import AuthError
    from app.banking.services import (
        TRANSFER_RISK_LARGE_TRANSFER,
        TRANSFER_RISK_NEW_PAYEE,
        TRANSFER_RISK_NORMAL,
        TRANSFER_STEP_UP_MFA,
        classify_transfer_risk,
        transfer_step_up_requirement,
    )

    assert classify_transfer_risk() == TRANSFER_RISK_NORMAL
    assert classify_transfer_risk(new_payee=True) == TRANSFER_RISK_NEW_PAYEE
    assert classify_transfer_risk(large_transfer=True) == TRANSFER_RISK_LARGE_TRANSFER
    assert transfer_step_up_requirement(TRANSFER_RISK_NORMAL) == TRANSFER_STEP_UP_MFA
    assert transfer_step_up_requirement(TRANSFER_RISK_NEW_PAYEE) == TRANSFER_STEP_UP_MFA
    assert transfer_step_up_requirement(TRANSFER_RISK_LARGE_TRANSFER) == TRANSFER_STEP_UP_MFA
    with pytest.raises(AuthError):
        transfer_step_up_requirement("unexpected")

def test_public_transaction_idempotency_binds_key_to_exact_payload():
    from app.auth.services import AuthError
    from app.banking.services import validate_public_transaction_payload

    store = {}
    payload = {
        "idempotency_key": "55555555-5555-4555-8555-555555555555",
        "amount": "25.00",
        "currency": "SGD",
        "payee": "PAYEE-002",
    }

    first = validate_public_transaction_payload(payload, idempotency_store=store)
    replay = validate_public_transaction_payload(dict(payload), idempotency_store=store)

    with pytest.raises(AuthError):
        validate_public_transaction_payload(
            {**payload, "amount": "30.00"},
            idempotency_store=store,
        )

    assert first == replay

def test_banking_transaction_approval_uses_required_audit_writer(app, monkeypatch):
    from app.banking import services as banking_services

    calls = []
    monkeypatch.setattr(
        banking_services,
        "audit_event_required",
        lambda event_type, outcome, **kwargs: calls.append((event_type, outcome, kwargs)),
    )
    monkeypatch.setattr(
        banking_services,
        "audit_event",
        lambda *_args, **_kwargs: pytest.fail("approval audit must be required"),
    )

    banking_services.audit_transaction_authorization(
        None,
        "approved",
        metadata={"decision": "approved"},
        transaction_reference="TXN-001",
    )

    assert calls
    assert calls[0][0] == "banking_transaction_authorization"
    assert calls[0][1] == "approved"
    assert calls[0][2]["metadata"]["decision"] == "approved"

def test_public_transaction_validation_audits_sanitized_success_and_failure(app):
    from app.auth.services import AuthError
    from app.banking.services import validate_public_transaction_payload

    with app.test_request_context("/banking/transactions", method="POST"):
        with pytest.raises(AuthError):
            validate_public_transaction_payload(
                {
                    "idempotency_key": "66666666-6666-4666-8666-666666666666",
                    "amount": "10.00",
                    "currency": "SGD",
                    "payee": "PAYEE-001",
                    "account_id": "server-controlled",
                }
            )
        validate_public_transaction_payload(
            {
                "idempotency_key": "77777777-7777-4777-8777-777777777777",
                "amount": "25.00",
                "currency": "SGD",
                "payee": "PAYEE-002",
            }
        )

    failure = (
        db.session.query(SecurityAuditEvent)
        .filter_by(event_type="banking_public_transaction_validation", outcome="failure")
        .one()
    )
    success = (
        db.session.query(SecurityAuditEvent)
        .filter_by(event_type="banking_public_transaction_validation", outcome="success")
        .one()
    )
    serialized = json.dumps([failure.event_metadata, success.event_metadata], sort_keys=True)

    assert failure.event_metadata["reason"] == "schema_validation_failed"
    assert "account_id" in failure.event_metadata["rejected_fields"]
    assert success.event_metadata["transaction_amount"] == "25.00"
    assert success.event_metadata["transaction_currency"] == "SGD"
    assert len(success.event_metadata["payload_hash_ref"]) == 32
    assert len(success.event_metadata["idempotency_key_ref"]) == 32
    assert len(success.event_metadata["payee_account_ref"]) == 32
    assert "66666666-6666-4666-8666-666666666666" not in serialized
    assert "77777777-7777-4777-8777-777777777777" not in serialized
    assert "PAYEE-001" not in serialized
    assert "PAYEE-002" not in serialized
