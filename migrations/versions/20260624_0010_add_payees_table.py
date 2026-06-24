"""Add payees table.

Revision ID: 20260624_0010
Revises: 20260624_0009
Create Date: 2026-06-24 00:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260624_0010"
down_revision = "20260624_0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "payees",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("nickname", sa.String(64), nullable=False),
        sa.Column("account_number", sa.String(9), nullable=False),
        sa.Column("recipient_name", sa.String(128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "account_number", name="uq_payees_user_account"),
    )
    op.create_index("ix_payees_user_id", "payees", ["user_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_payees_user_id", table_name="payees")
    op.drop_table("payees")
