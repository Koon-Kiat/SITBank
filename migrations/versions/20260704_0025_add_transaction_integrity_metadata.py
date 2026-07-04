"""Add versioned keyed transaction integrity metadata.

Revision ID: 20260704_0025
Revises: 20260703_0024
Create Date: 2026-07-04 12:00:00
"""

import sqlalchemy as sa
from alembic import op


revision = "20260704_0025"
down_revision = "20260703_0024"
branch_labels = None
depends_on = None


_INTEGRITY_CHECK = (
    "(transaction_integrity_key_id IS NULL "
    "AND transaction_integrity_algorithm IS NULL "
    "AND transaction_integrity_version IS NULL) OR "
    "(transaction_integrity_key_id IS NOT NULL "
    "AND transaction_integrity_algorithm = 'hmac-sha256' "
    "AND transaction_integrity_version = 1)"
)


def upgrade() -> None:
    if op.get_context().as_sql:
        op.add_column(
            "transactions",
            sa.Column("transaction_integrity_key_id", sa.String(length=32), nullable=True),
        )
        op.add_column(
            "transactions",
            sa.Column(
                "transaction_integrity_algorithm",
                sa.String(length=32),
                nullable=True,
            ),
        )
        op.add_column(
            "transactions",
            sa.Column("transaction_integrity_version", sa.Integer(), nullable=True),
        )
        if op.get_context().dialect.name == "postgresql":
            op.create_check_constraint(
                "ck_transactions_integrity_metadata",
                "transactions",
                _INTEGRITY_CHECK,
            )
        else:
            op.execute(
                "-- SQLite offline SQL cannot add the transaction integrity "
                "check constraint portably."
            )
        return
    with op.batch_alter_table("transactions") as batch_op:
        batch_op.add_column(
            sa.Column("transaction_integrity_key_id", sa.String(length=32), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "transaction_integrity_algorithm",
                sa.String(length=32),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column("transaction_integrity_version", sa.Integer(), nullable=True)
        )
        batch_op.create_check_constraint(
            "ck_transactions_integrity_metadata",
            _INTEGRITY_CHECK,
        )


def downgrade() -> None:
    if op.get_context().as_sql:
        if op.get_context().dialect.name == "postgresql":
            op.drop_constraint(
                "ck_transactions_integrity_metadata",
                "transactions",
                type_="check",
            )
            op.drop_column("transactions", "transaction_integrity_version")
            op.drop_column("transactions", "transaction_integrity_algorithm")
            op.drop_column("transactions", "transaction_integrity_key_id")
        else:
            op.execute(
                "-- SQLite offline SQL cannot drop transaction integrity "
                "columns portably."
            )
        return
    with op.batch_alter_table("transactions") as batch_op:
        batch_op.drop_constraint(
            "ck_transactions_integrity_metadata",
            type_="check",
        )
        batch_op.drop_column("transaction_integrity_version")
        batch_op.drop_column("transaction_integrity_algorithm")
        batch_op.drop_column("transaction_integrity_key_id")
