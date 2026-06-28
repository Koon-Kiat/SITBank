"""Add pending_transfers table and financial integrity constraints.

Revision ID: 20260628_0016
Revises: 20260627_0015
Create Date: 2026-06-28 00:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260628_0016"
down_revision = "20260627_0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "pending_transfers",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("token", sa.String(64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("payee_id", sa.Integer(), nullable=False),
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
        sa.UniqueConstraint("token", name="uq_pending_transfers_token"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["payee_id"], ["payees.id"]),
    )
    op.create_index("ix_pending_transfers_token", "pending_transfers", ["token"], unique=True)
    op.create_index("ix_pending_transfers_user_id", "pending_transfers", ["user_id"])
    op.create_index("ix_pending_transfers_payee_id", "pending_transfers", ["payee_id"])
    op.create_index("ix_pending_transfers_expires_at", "pending_transfers", ["expires_at"])

    with op.batch_alter_table("transactions") as batch_op:
        batch_op.add_column(sa.Column("transaction_hash", sa.String(64), nullable=True))
    op.create_index(
        "ix_transactions_transaction_hash",
        "transactions",
        ["transaction_hash"],
        unique=True,
    )

    # CHECK constraints require ALTER TABLE ADD CONSTRAINT, which PostgreSQL supports
    # natively. SQLite cannot add CHECK constraints to existing tables without
    # recreating them, and batch_alter_table cannot reflect the schema in offline
    # (--sql) mode. The application-layer service enforces these invariants for SQLite.
    if op.get_context().dialect.name == "postgresql":
        op.execute(sa.text(
            "ALTER TABLE users ADD CONSTRAINT ck_users_balance_non_negative"
            " CHECK (balance >= 0)"
        ))
        op.execute(sa.text(
            "ALTER TABLE transactions ADD CONSTRAINT ck_transactions_amount_positive"
            " CHECK (amount > 0)"
        ))


def downgrade() -> None:
    if op.get_context().dialect.name == "postgresql":
        op.execute(sa.text(
            "ALTER TABLE transactions DROP CONSTRAINT ck_transactions_amount_positive"
        ))
        op.execute(sa.text(
            "ALTER TABLE users DROP CONSTRAINT ck_users_balance_non_negative"
        ))

    op.drop_index("ix_transactions_transaction_hash", table_name="transactions")
    with op.batch_alter_table("transactions") as batch_op:
        batch_op.drop_column("transaction_hash")

    op.drop_index("ix_pending_transfers_expires_at", table_name="pending_transfers")
    op.drop_index("ix_pending_transfers_payee_id", table_name="pending_transfers")
    op.drop_index("ix_pending_transfers_user_id", table_name="pending_transfers")
    op.drop_index("ix_pending_transfers_token", table_name="pending_transfers")
    op.drop_table("pending_transfers")
