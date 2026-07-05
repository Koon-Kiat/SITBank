from __future__ import annotations

from pathlib import Path

from app.models import PublicTransactionIdempotency


MIGRATION = Path(
    "migrations/versions/20260705_0029_public_transaction_idempotency.py"
)


def test_public_transaction_idempotency_model_is_scoped_and_expiring():
    columns = PublicTransactionIdempotency.__table__.c

    assert columns.user_id.nullable is False
    assert columns.hmac_key_id.nullable is False
    assert columns.key_fingerprint.nullable is False
    assert columns.key_verifier.nullable is False
    assert columns.payload_verifier.nullable is False
    assert columns.status.nullable is False
    assert columns.result_reference.nullable is True
    assert columns.created_at.nullable is False
    assert columns.updated_at.nullable is False
    assert columns.expires_at.nullable is False

    constraints = {
        constraint.name
        for constraint in PublicTransactionIdempotency.__table__.constraints
    }
    assert "uq_public_transaction_idempotency_user_key" in constraints
    assert "ck_public_transaction_idempotency_status" in constraints


def test_public_transaction_idempotency_migration_is_chained_and_fail_closed():
    text = MIGRATION.read_text(encoding="utf-8")

    assert 'revision = "20260705_0029"' in text
    assert 'down_revision = "20260705_0028"' in text
    assert '"public_transaction_idempotency"' in text
    assert '"hmac_key_id"' in text
    assert '"key_fingerprint"' in text
    assert '"key_verifier"' in text
    assert '"payload_verifier"' in text
    assert 'ondelete="CASCADE"' in text
    assert "Downgrade would discard durable public transaction replay state" in text
