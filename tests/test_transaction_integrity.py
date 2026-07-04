from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from types import SimpleNamespace

import pytest

from app.security.transaction_integrity import (
    TRANSACTION_INTEGRITY_ALGORITHM,
    TRANSACTION_INTEGRITY_VERSION,
    sign_transaction_integrity,
    transaction_integrity_status,
    validate_transaction_integrity_config,
)


def _signed_transaction(**overrides):
    fields = {
        "transaction_ref": "11111111-2222-4333-8444-555555555555",
        "sender_id": 1,
        "recipient_id": 2,
        "payee_id": 3,
        "amount": Decimal("10.00"),
        "reference": "Clearly fake reference",
        "status": "completed",
        "transaction_type": "local_transfer",
        "created_at": datetime(2026, 7, 4, 12, 30, tzinfo=timezone.utc),
    }
    fields.update(overrides)
    digest, key_id, algorithm, version = sign_transaction_integrity(**fields)
    return SimpleNamespace(
        **fields,
        transaction_hash=digest,
        transaction_integrity_key_id=key_id,
        transaction_integrity_algorithm=algorithm,
        transaction_integrity_version=version,
    )


def test_transaction_integrity_uses_dedicated_versioned_keyring(app):
    with app.app_context():
        transaction = _signed_transaction()

        assert transaction_integrity_status(transaction) == "valid"
        assert transaction.transaction_integrity_algorithm == TRANSACTION_INTEGRITY_ALGORITHM
        assert transaction.transaction_integrity_version == TRANSACTION_INTEGRITY_VERSION
        assert transaction.transaction_integrity_key_id == app.config[
            "TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID"
        ]
        assert validate_transaction_integrity_config() == 2


def test_transaction_type_is_covered_by_integrity_digest(app):
    with app.app_context():
        local_transfer = _signed_transaction(transaction_type="local_transfer")
        payup = _signed_transaction(transaction_type="payup", payee_id=None)

    assert local_transfer.transaction_hash != payup.transaction_hash


@pytest.mark.parametrize(
    ("field", "tampered_value"),
    [
        ("transaction_ref", "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
        ("sender_id", 9),
        ("recipient_id", 9),
        ("payee_id", 9),
        ("amount", Decimal("10.01")),
        ("reference", "Tampered reference"),
        ("status", "failed"),
        ("transaction_type", "payup"),
        ("created_at", datetime(2026, 7, 4, 12, 31, tzinfo=timezone.utc)),
    ],
)
def test_transaction_integrity_detects_stored_field_tampering(
    app,
    field,
    tampered_value,
):
    with app.app_context():
        transaction = _signed_transaction()
        setattr(transaction, field, tampered_value)

        assert transaction_integrity_status(transaction) == "invalid"


def test_transaction_integrity_rejects_partial_unknown_and_missing_keys(app):
    with app.app_context():
        partial = _signed_transaction()
        partial.transaction_integrity_algorithm = None
        assert transaction_integrity_status(partial) == "invalid"

        unsupported = _signed_transaction()
        unsupported.transaction_integrity_algorithm = "unsupported"
        assert transaction_integrity_status(unsupported) == "invalid"

        unknown = _signed_transaction()
        unknown.transaction_integrity_key_id = "retired-unknown"
        assert transaction_integrity_status(unknown) == "invalid"

        configured_keys = app.config["TRANSACTION_LEDGER_HMAC_KEYS"]
        app.config["TRANSACTION_LEDGER_HMAC_KEYS"] = {}
        try:
            assert transaction_integrity_status(unknown) == "invalid"
            with pytest.raises(RuntimeError, match="transaction ledger HMAC key"):
                validate_transaction_integrity_config()
        finally:
            app.config["TRANSACTION_LEDGER_HMAC_KEYS"] = configured_keys

        active_key_id = app.config["TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID"]
        app.config["TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID"] = "missing"
        try:
            with pytest.raises(RuntimeError, match="must identify a configured key"):
                validate_transaction_integrity_config()
        finally:
            app.config["TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID"] = active_key_id

        app.config["TRANSACTION_LEDGER_HMAC_KEYS"] = {"invalid": b"short"}
        app.config["TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID"] = "invalid"
        try:
            with pytest.raises(RuntimeError, match="must have an identifier"):
                validate_transaction_integrity_config()
        finally:
            app.config["TRANSACTION_LEDGER_HMAC_KEYS"] = configured_keys
            app.config["TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID"] = active_key_id


def test_rows_without_integrity_metadata_are_explicitly_legacy(app):
    legacy = SimpleNamespace(
        transaction_integrity_key_id=None,
        transaction_integrity_algorithm=None,
        transaction_integrity_version=None,
    )
    with app.app_context():
        assert transaction_integrity_status(legacy) == "legacy"
