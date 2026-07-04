from __future__ import annotations

from pathlib import Path

from app.models import DISPUTE_ISSUE_TYPES, DISPUTE_OPEN_STATUSES, TransactionDispute


MIGRATIONS = Path("migrations/versions")
DISPUTES_MIGRATION = MIGRATIONS / "20260705_0027_add_transaction_disputes.py"


def test_transaction_dispute_model_columns_match_expected_shape():
    columns = TransactionDispute.__table__.c

    assert columns.transaction_id.nullable is False
    assert columns.reporter_id.nullable is False
    assert columns.issue_type.nullable is False
    assert columns.reason.nullable is False
    assert columns.status.nullable is False
    assert columns.resolver_id.nullable is True
    assert columns.resolution_note.nullable is True
    assert columns.decided_at.nullable is True


def test_transaction_dispute_status_never_touches_transaction_status():
    assert "transaction_disputes" == TransactionDispute.__tablename__
    assert DISPUTE_ISSUE_TYPES == (
        "unauthorized_transaction",
        "duplicate_charge",
        "incorrect_amount",
        "recipient_service_issue",
        "other",
    )
    assert DISPUTE_OPEN_STATUSES == ("open", "under_review")


def test_transaction_disputes_migration_is_chained_and_portable():
    text = DISPUTES_MIGRATION.read_text(encoding="utf-8")

    assert 'revision = "20260705_0027"' in text
    assert 'down_revision = "20260704_0026"' in text
    assert '"transaction_disputes"' in text
    assert "postgresql_where=" in text
    assert "sqlite_where=" in text
    assert "ux_transaction_disputes_one_open_per_txn" in text
