"""Add transaction dispute reporting table.

Revision ID: 20260705_0027
Revises: 20260704_0026
Create Date: 2026-07-05 00:27:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260705_0027"
down_revision = "20260704_0026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "transaction_disputes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("transaction_id", sa.Integer(), nullable=False),
        sa.Column("reporter_id", sa.Integer(), nullable=False),
        sa.Column("issue_type", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("resolver_id", sa.Integer(), nullable=True),
        sa.Column("resolution_note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "issue_type IN ('unauthorized_transaction', 'duplicate_charge', 'incorrect_amount', "
            "'recipient_service_issue', 'other')",
            name="ck_transaction_disputes_issue_type",
        ),
        sa.CheckConstraint(
            "status IN ('open', 'under_review', 'resolved', 'rejected')",
            name="ck_transaction_disputes_status",
        ),
        sa.ForeignKeyConstraint(["transaction_id"], ["transactions.id"]),
        sa.ForeignKeyConstraint(["reporter_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["resolver_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_transaction_disputes_transaction_id", "transaction_disputes", ["transaction_id"]
    )
    op.create_index(
        "ix_transaction_disputes_reporter_id", "transaction_disputes", ["reporter_id"]
    )
    op.create_index(
        "ix_transaction_disputes_status", "transaction_disputes", ["status"]
    )
    op.create_index(
        "ix_transaction_disputes_resolver_id", "transaction_disputes", ["resolver_id"]
    )
    op.create_index(
        "ix_transaction_disputes_created_at", "transaction_disputes", ["created_at"]
    )
    op.create_index(
        "ux_transaction_disputes_one_open_per_txn",
        "transaction_disputes",
        ["transaction_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('open', 'under_review')"),
        sqlite_where=sa.text("status IN ('open', 'under_review')"),
    )


def downgrade() -> None:
    op.drop_index("ux_transaction_disputes_one_open_per_txn", table_name="transaction_disputes")
    op.drop_index("ix_transaction_disputes_created_at", table_name="transaction_disputes")
    op.drop_index("ix_transaction_disputes_resolver_id", table_name="transaction_disputes")
    op.drop_index("ix_transaction_disputes_status", table_name="transaction_disputes")
    op.drop_index("ix_transaction_disputes_reporter_id", table_name="transaction_disputes")
    op.drop_index("ix_transaction_disputes_transaction_id", table_name="transaction_disputes")
    op.drop_table("transaction_disputes")
