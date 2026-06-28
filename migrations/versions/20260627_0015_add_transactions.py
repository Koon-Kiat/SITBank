"""Add balance to users and create transactions table.

Revision ID: 20260627_0015
Revises: 20260626_0014
Create Date: 2026-06-27 00:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260627_0015"
down_revision = "20260626_0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "balance",
            sa.Numeric(precision=12, scale=2),
            nullable=False,
            server_default="0.00",
        ),
    )

    op.create_table(
        "transactions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("transaction_ref", sa.String(36), nullable=False),
        sa.Column("sender_id", sa.Integer(), nullable=False),
        sa.Column("recipient_id", sa.Integer(), nullable=False),
        sa.Column("payee_id", sa.Integer(), nullable=True),
        sa.Column("amount", sa.Numeric(precision=12, scale=2), nullable=False),
        sa.Column("reference", sa.String(128), nullable=False, server_default=""),
        sa.Column("status", sa.String(32), nullable=False, server_default="completed"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["sender_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["recipient_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["payee_id"], ["payees.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("transaction_ref", name="uq_transactions_ref"),
        sa.CheckConstraint(
            "status IN ('completed', 'failed')",
            name="ck_transactions_status",
        ),
    )
    op.create_index("ix_transactions_transaction_ref", "transactions", ["transaction_ref"])
    op.create_index("ix_transactions_sender_id", "transactions", ["sender_id"])
    op.create_index("ix_transactions_recipient_id", "transactions", ["recipient_id"])
    op.create_index("ix_transactions_payee_id", "transactions", ["payee_id"])
    op.create_index("ix_transactions_created_at", "transactions", ["created_at"])


def downgrade() -> None:
    op.drop_table("transactions")
    op.drop_column("users", "balance")
