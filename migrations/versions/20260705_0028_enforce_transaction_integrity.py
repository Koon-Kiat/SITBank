"""Enforce keyed integrity metadata on every transaction.

Revision ID: 20260705_0028
Revises: 20260705_0027
Create Date: 2026-07-05 12:00:00
"""

import sqlalchemy as sa
from alembic import op


revision = "20260705_0028"
down_revision = "20260705_0027"
branch_labels = None
depends_on = None


_INTEGRITY_CHECK = (
    "transaction_integrity_key_id IS NOT NULL "
    "AND transaction_integrity_algorithm = 'hmac-sha256' "
    "AND transaction_integrity_version = 1"
)


def _refuse_unbackfilled_rows() -> None:
    if op.get_context().as_sql:
        return
    invalid_count = op.get_bind().execute(
        sa.text(
            "SELECT COUNT(*) FROM transactions "
            "WHERE transaction_integrity_key_id IS NULL "
            "OR transaction_integrity_algorithm IS NULL "
            "OR transaction_integrity_version IS NULL "
            "OR transaction_integrity_algorithm <> 'hmac-sha256' "
            "OR transaction_integrity_version <> 1"
        )
    ).scalar_one()
    if int(invalid_count):
        raise RuntimeError(
            "Transaction integrity enforcement requires the controlled "
            "backfill command before database upgrade"
        )


def upgrade() -> None:
    _refuse_unbackfilled_rows()
    op.add_column(
        "users",
        sa.Column(
            "payup_enabled",
            sa.Boolean(),
            server_default=sa.true(),
            nullable=False,
        ),
    )
    if (
        op.get_context().as_sql
        and op.get_context().dialect.name != "postgresql"
    ):
        op.execute(
            "-- SQLite offline SQL cannot enforce transaction integrity "
            "NOT NULL/check constraints portably."
        )
        return
    with op.batch_alter_table("transactions") as batch_op:
        batch_op.drop_constraint(
            "ck_transactions_integrity_metadata",
            type_="check",
        )
        batch_op.alter_column(
            "transaction_integrity_key_id",
            existing_type=sa.String(length=32),
            nullable=False,
        )
        batch_op.alter_column(
            "transaction_integrity_algorithm",
            existing_type=sa.String(length=32),
            nullable=False,
        )
        batch_op.alter_column(
            "transaction_integrity_version",
            existing_type=sa.Integer(),
            nullable=False,
        )
        batch_op.create_check_constraint(
            "ck_transactions_integrity_metadata",
            _INTEGRITY_CHECK,
        )


def downgrade() -> None:
    raise RuntimeError(
        "Downgrade would re-enable legacy transaction integrity metadata and "
        "requires an explicit security-reviewed migration"
    )
