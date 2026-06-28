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
        sa.Column("amount", sa.Numeric(precision=12, scale=2), nullable=False),
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

    with op.batch_alter_table("users") as batch_op:
        batch_op.create_check_constraint(
            "ck_users_balance_non_negative",
            "balance >= 0",
        )

    with op.batch_alter_table("transactions") as batch_op:
        batch_op.add_column(sa.Column("transaction_hash", sa.String(64), nullable=True))
        batch_op.create_check_constraint(
            "ck_transactions_amount_positive",
            "amount > 0",
        )
    op.create_index(
        "ix_transactions_transaction_hash",
        "transactions",
        ["transaction_hash"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_transactions_transaction_hash", table_name="transactions")
    with op.batch_alter_table("transactions") as batch_op:
        batch_op.drop_column("transaction_hash")
        batch_op.drop_constraint("ck_transactions_amount_positive", type_="check")

    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_constraint("ck_users_balance_non_negative", type_="check")

    op.drop_index("ix_pending_transfers_expires_at", table_name="pending_transfers")
    op.drop_index("ix_pending_transfers_payee_id", table_name="pending_transfers")
    op.drop_index("ix_pending_transfers_user_id", table_name="pending_transfers")
    op.drop_index("ix_pending_transfers_token", table_name="pending_transfers")
    op.drop_table("pending_transfers")
