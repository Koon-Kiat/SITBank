"""Add PayUp support: daily limit, transaction type, pending transfers.

Revision ID: 20260703_0022
Revises: 20260702_0021
Create Date: 2026-07-03 00:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260703_0022"
down_revision = "20260702_0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "payup_daily_limit",
            sa.Numeric(precision=10, scale=2),
            nullable=False,
            server_default="500.00",
        ),
    )

    op.add_column(
        "transactions",
        sa.Column(
            "transaction_type",
            sa.String(32),
            nullable=False,
            server_default="local_transfer",
        ),
    )

    # CHECK constraints require ALTER TABLE ADD CONSTRAINT, which PostgreSQL supports
    # natively. SQLite cannot add CHECK constraints to existing tables without
    # recreating them, and batch_alter_table cannot reflect the schema in offline
    # (--sql) mode. The application-layer service enforces this invariant for SQLite,
    # matching the precedent set in 20260628_0016_harden_local_transfer.py.
    if op.get_context().dialect.name == "postgresql":
        op.execute(sa.text(
            "ALTER TABLE transactions ADD CONSTRAINT ck_transactions_transaction_type"
            " CHECK (transaction_type IN ('local_transfer', 'payup'))"
        ))

    op.create_table(
        "payup_pending_transfers",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("token", sa.String(64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("recipient_user_id", sa.Integer(), nullable=False),
        sa.Column("amount", sa.Numeric(precision=12, scale=5), nullable=False),
        sa.Column("reference", sa.String(128), nullable=False, server_default=""),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_transaction_ref", sa.String(36), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token", name="uq_payup_pending_transfers_token"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["recipient_user_id"], ["users.id"]),
    )
    op.create_index(
        "ix_payup_pending_transfers_token", "payup_pending_transfers", ["token"], unique=True
    )
    op.create_index(
        "ix_payup_pending_transfers_user_id", "payup_pending_transfers", ["user_id"]
    )
    op.create_index(
        "ix_payup_pending_transfers_recipient_user_id",
        "payup_pending_transfers",
        ["recipient_user_id"],
    )
    op.create_index(
        "ix_payup_pending_transfers_expires_at", "payup_pending_transfers", ["expires_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_payup_pending_transfers_expires_at", table_name="payup_pending_transfers")
    op.drop_index(
        "ix_payup_pending_transfers_recipient_user_id", table_name="payup_pending_transfers"
    )
    op.drop_index("ix_payup_pending_transfers_user_id", table_name="payup_pending_transfers")
    op.drop_index("ix_payup_pending_transfers_token", table_name="payup_pending_transfers")
    op.drop_table("payup_pending_transfers")

    if op.get_context().dialect.name == "postgresql":
        op.execute(sa.text(
            "ALTER TABLE transactions DROP CONSTRAINT ck_transactions_transaction_type"
        ))

    op.drop_column("transactions", "transaction_type")
    op.drop_column("users", "payup_daily_limit")
