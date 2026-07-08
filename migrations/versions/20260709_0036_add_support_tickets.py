"""Add support tickets table and optional recovery-request reason field.

Revision ID: 20260709_0036
Revises: 20260708_0035
Create Date: 2026-07-09 00:36:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260709_0036"
down_revision = "20260708_0035"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "support_tickets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("subject", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("resolved_by_user_id", sa.Integer(), nullable=True),
        sa.Column("resolution_note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "category IN ('enquiry', 'security_concern', 'other')",
            name="ck_support_tickets_category",
        ),
        sa.CheckConstraint(
            "status IN ('open', 'in_review', 'resolved', 'closed')",
            name="ck_support_tickets_status",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["resolved_by_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_support_tickets_user_id", "support_tickets", ["user_id"])
    op.create_index("ix_support_tickets_status", "support_tickets", ["status"])
    op.create_index("ix_support_tickets_resolved_by_user_id", "support_tickets", ["resolved_by_user_id"])
    op.create_index("ix_support_tickets_created_at", "support_tickets", ["created_at"])

    with op.batch_alter_table("manual_recovery_requests") as batch_op:
        batch_op.add_column(sa.Column("reason", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("manual_recovery_requests") as batch_op:
        batch_op.drop_column("reason")

    op.drop_index("ix_support_tickets_created_at", table_name="support_tickets")
    op.drop_index("ix_support_tickets_resolved_by_user_id", table_name="support_tickets")
    op.drop_index("ix_support_tickets_status", table_name="support_tickets")
    op.drop_index("ix_support_tickets_user_id", table_name="support_tickets")
    op.drop_table("support_tickets")
