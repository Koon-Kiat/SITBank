"""Add password history to the current reset-only user schema.

Revision ID: 20260701_0019
Revises: 20260628_0016
Create Date: 2026-07-01 00:19:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260701_0019"
down_revision = "20260628_0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "password_changed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.add_column(
        "users",
        sa.Column(
            "force_password_change",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column("users", sa.Column("force_password_change_reason", sa.String(length=80), nullable=True))
    op.add_column("users", sa.Column("force_password_change_at", sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        "password_history",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_password_history_user_id", "password_history", ["user_id"])
    op.create_index("ix_password_history_created_at", "password_history", ["created_at"])
    op.create_index(
        "ix_password_history_user_created_at",
        "password_history",
        ["user_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_password_history_user_created_at", table_name="password_history")
    op.drop_index("ix_password_history_created_at", table_name="password_history")
    op.drop_index("ix_password_history_user_id", table_name="password_history")
    op.drop_table("password_history")

    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("force_password_change_at")
        batch_op.drop_column("force_password_change_reason")
        batch_op.drop_column("force_password_change")
        batch_op.drop_column("password_changed_at")
