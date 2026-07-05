from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from types import SimpleNamespace

import pytest

from app.ops import commands
from app.security.transaction_integrity import (
    TRANSACTION_INTEGRITY_ALGORITHM,
    TRANSACTION_INTEGRITY_VERSION,
    registration_credit_integrity_status,
    sign_registration_credit_integrity,
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


def _signed_registration_credit(**overrides):
    fields = {
        "credit_ref": "22222222-3333-4444-8555-666666666666",
        "user_id": 42,
        "amount": Decimal("100.00"),
        "status": "completed",
        "created_at": datetime(2026, 7, 4, 13, 30, tzinfo=timezone.utc),
    }
    fields.update(overrides)
    digest, key_id, algorithm, version = sign_registration_credit_integrity(**fields)
    return SimpleNamespace(
        **fields,
        credit_hash=digest,
        credit_integrity_key_id=key_id,
        credit_integrity_algorithm=algorithm,
        credit_integrity_version=version,
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


def test_registration_credit_integrity_detects_amount_tampering(app):
    with app.app_context():
        credit = _signed_registration_credit()
        assert registration_credit_integrity_status(credit) == "valid"

        credit.amount = Decimal("100.01")

        assert registration_credit_integrity_status(credit) == "invalid"


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


def test_rows_without_integrity_metadata_fail_closed(app):
    legacy = SimpleNamespace(
        transaction_integrity_key_id=None,
        transaction_integrity_algorithm=None,
        transaction_integrity_version=None,
    )
    with app.app_context():
        assert transaction_integrity_status(legacy) == "invalid"


def _legacy_transaction():
    return SimpleNamespace(
        id=1,
        transaction_ref="11111111-2222-4333-8444-555555555555",
        transaction_hash="0" * 64,
        transaction_integrity_key_id=None,
        transaction_integrity_algorithm=None,
        transaction_integrity_version=None,
        sender_id=1,
        recipient_id=2,
        payee_id=None,
        amount=Decimal("10.00"),
        reference="Clearly fake reference",
        status="completed",
        transaction_type="payup",
        created_at=datetime(2026, 7, 4, 12, 30, tzinfo=timezone.utc),
    )


class _BackfillStatement:
    def order_by(self, *_args):
        return self

    def with_for_update(self):
        return self


class _BackfillSession:
    def __init__(self, rows):
        self.rows = rows
        self.flush_count = 0
        self.commit_count = 0
        self.rollback_count = 0

    def execute(self, _statement):
        return SimpleNamespace(scalars=lambda: self.rows)

    def flush(self):
        self.flush_count += 1

    def commit(self):
        self.commit_count += 1

    def rollback(self):
        self.rollback_count += 1


def test_controlled_transaction_integrity_backfill_is_dry_run_by_default(
    app,
    monkeypatch,
):
    transaction = _legacy_transaction()
    session = _BackfillSession([transaction])
    events = []
    monkeypatch.setattr(
        commands,
        "db",
        SimpleNamespace(
            select=lambda _model: _BackfillStatement(),
            session=session,
            engine=SimpleNamespace(dialect=SimpleNamespace(name="sqlite")),
        ),
    )
    monkeypatch.setattr(
        commands,
        "audit_system_event",
        lambda *args, **kwargs: events.append((args, kwargs)),
    )

    with app.app_context():
        result = commands._backfill_transaction_integrity(confirm=False)

    assert result == {
        "message": "transaction_integrity_backfill",
        "mode": "dry_run",
        "scanned_count": 1,
        "backfilled_count": 0,
        "backfill_required_count": 1,
        "valid_existing_count": 0,
    }
    assert transaction.transaction_integrity_key_id is None
    assert session.commit_count == 0
    assert session.rollback_count == 1
    assert events[0][0][:2] == ("transaction_integrity_backfill", "dry_run")


def test_controlled_transaction_integrity_backfill_signs_and_commits_atomically(
    app,
    monkeypatch,
):
    transaction = _legacy_transaction()
    session = _BackfillSession([transaction])
    events = []
    committed_event = object()
    monkeypatch.setattr(
        commands,
        "db",
        SimpleNamespace(
            select=lambda _model: _BackfillStatement(),
            session=session,
            engine=SimpleNamespace(dialect=SimpleNamespace(name="postgresql")),
        ),
    )
    monkeypatch.setattr(
        commands,
        "audit_system_event_required",
        lambda *args, **kwargs: events.append((args, kwargs)),
    )
    monkeypatch.setattr(
        commands,
        "audit_system_event_in_transaction_required",
        lambda *args, **kwargs: committed_event,
    )
    logged = []
    monkeypatch.setattr(
        commands,
        "log_committed_system_audit_event",
        lambda event: logged.append(event),
    )

    with app.app_context():
        result = commands._backfill_transaction_integrity(confirm=True)
        assert transaction_integrity_status(transaction) == "valid"

    assert result["backfilled_count"] == 1
    assert result["backfill_required_count"] == 0
    assert session.flush_count == 1
    assert session.commit_count == 1
    assert session.rollback_count == 0
    assert events[0][0][:2] == ("transaction_integrity_backfill", "started")
    assert logged == [committed_event]


def test_controlled_transaction_integrity_backfill_rejects_partial_metadata(
    app,
    monkeypatch,
):
    transaction = _legacy_transaction()
    transaction.transaction_integrity_key_id = "test-ledger-current"
    session = _BackfillSession([transaction])
    failed_events = []
    monkeypatch.setattr(
        commands,
        "db",
        SimpleNamespace(
            select=lambda _model: _BackfillStatement(),
            session=session,
            engine=SimpleNamespace(dialect=SimpleNamespace(name="sqlite")),
        ),
    )
    monkeypatch.setattr(commands, "audit_system_event_required", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        commands,
        "audit_system_event",
        lambda *args, **kwargs: failed_events.append((args, kwargs)),
    )

    with app.app_context(), pytest.raises(RuntimeError, match="partial metadata"):
        commands._backfill_transaction_integrity(confirm=True)

    assert session.commit_count == 0
    assert session.rollback_count == 1
    assert failed_events[0][0][:2] == ("transaction_integrity_backfill", "failed")
