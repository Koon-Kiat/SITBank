"""Align model metadata with the production migration baseline.

Revision ID: 20260702_0020
Revises: 20260701_0019
Create Date: 2026-07-02 00:20:00
"""

from __future__ import annotations

import hashlib
import json

from alembic import op
import sqlalchemy as sa


revision = "20260702_0020"
down_revision = "20260701_0019"
branch_labels = None
depends_on = None


def _transaction_hash(row: sa.Row) -> str:
    canonical = json.dumps(
        {
            "amount": str(row.amount),
            "created_at": row.created_at.isoformat(),
            "recipient_id": row.recipient_id,
            "reference": row.reference or "",
            "sender_id": row.sender_id,
            "transaction_ref": row.transaction_ref,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _backfill_transaction_hashes() -> None:
    if op.get_context().as_sql:
        op.execute(
            "-- Online migration recomputes missing transaction_hash values "
            "from canonical transaction fields before enforcing NOT NULL."
        )
        return

    bind = op.get_bind()
    transactions = sa.table(
        "transactions",
        sa.column("id", sa.Integer()),
        sa.column("transaction_ref", sa.String(length=36)),
        sa.column("sender_id", sa.Integer()),
        sa.column("recipient_id", sa.Integer()),
        sa.column("amount", sa.Numeric(precision=12, scale=2)),
        sa.column("reference", sa.String(length=128)),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("transaction_hash", sa.String(length=64)),
    )
    rows = bind.execute(
        sa.select(
            transactions.c.id,
            transactions.c.transaction_ref,
            transactions.c.sender_id,
            transactions.c.recipient_id,
            transactions.c.amount,
            transactions.c.reference,
            transactions.c.created_at,
        )
        .where(transactions.c.transaction_hash.is_(None))
        .order_by(transactions.c.id)
    ).fetchall()
    for row in rows:
        bind.execute(
            transactions.update()
            .where(transactions.c.id == row.id)
            .values(transaction_hash=_transaction_hash(row))
        )


def upgrade() -> None:
    _backfill_transaction_hashes()
    if op.get_context().as_sql and op.get_context().dialect.name != "postgresql":
        op.execute("-- SQLite offline SQL cannot render ALTER COLUMN NOT NULL portably.")
        return

    with op.batch_alter_table("transactions") as batch_op:
        batch_op.alter_column(
            "transaction_hash",
            existing_type=sa.String(length=64),
            nullable=False,
        )


def downgrade() -> None:
    if op.get_context().as_sql and op.get_context().dialect.name != "postgresql":
        op.execute("-- SQLite offline SQL cannot render ALTER COLUMN NULL portably.")
        return

    with op.batch_alter_table("transactions") as batch_op:
        batch_op.alter_column(
            "transaction_hash",
            existing_type=sa.String(length=64),
            nullable=True,
        )
