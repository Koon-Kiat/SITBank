"""Allow 'topup' in transactions.transaction_type so top-ups appear in history.

Revision ID: 20260708_0034
Revises: 20260708_0033
Create Date: 2026-07-08 00:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260708_0034"
down_revision = "20260708_0033"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # See 20260703_0022_add_payup_support.py for why this is Postgres-only:
    # SQLite cannot ALTER an existing CHECK constraint, and the application
    # layer only ever writes a validated transaction_type value.
    if op.get_context().dialect.name == "postgresql":
        op.execute(sa.text(
            "ALTER TABLE transactions DROP CONSTRAINT ck_transactions_transaction_type"
        ))
        op.execute(sa.text(
            "ALTER TABLE transactions ADD CONSTRAINT ck_transactions_transaction_type"
            " CHECK (transaction_type IN ('local_transfer', 'payup', 'topup'))"
        ))


def downgrade() -> None:
    # Lossy if any 'topup' rows exist: re-adding the narrower constraint will
    # fail until those rows are removed or recategorized. Matches the
    # best-effort precedent in 20260703_0022_add_payup_support.py.
    if op.get_context().dialect.name == "postgresql":
        op.execute(sa.text(
            "ALTER TABLE transactions DROP CONSTRAINT ck_transactions_transaction_type"
        ))
        op.execute(sa.text(
            "ALTER TABLE transactions ADD CONSTRAINT ck_transactions_transaction_type"
            " CHECK (transaction_type IN ('local_transfer', 'payup'))"
        ))
