"""Add current customer registration fields to an empty reset schema.

Revision ID: 20260622_0008
Revises: 20260620_0006
Create Date: 2026-06-22 00:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260622_0008"
down_revision = "20260620_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if op.get_context().as_sql:
        op.add_column("users", sa.Column("full_name", sa.String(128), nullable=False))
        op.add_column("users", sa.Column("phone_number", sa.String(8), nullable=True))
        op.add_column("users", sa.Column("account_number", sa.String(12), nullable=True))
    else:
        with op.batch_alter_table("users") as batch_op:
            batch_op.add_column(sa.Column("full_name", sa.String(128), nullable=True))
            batch_op.add_column(sa.Column("phone_number", sa.String(8), nullable=True))
            batch_op.add_column(sa.Column("account_number", sa.String(12), nullable=True))
            batch_op.alter_column("full_name", existing_type=sa.String(128), nullable=False)

    op.create_index(
        "ix_users_phone_number",
        "users",
        ["phone_number"],
        unique=True,
        if_not_exists=True,
        postgresql_where=sa.text("phone_number IS NOT NULL"),
        sqlite_where=sa.text("phone_number IS NOT NULL"),
    )
    op.create_index("ix_users_account_number", "users", ["account_number"], unique=True, if_not_exists=True)


def downgrade() -> None:
    op.drop_index("ix_users_account_number", table_name="users")
    op.drop_index("ix_users_phone_number", table_name="users")
    op.drop_column("users", "account_number")
    op.drop_column("users", "phone_number")
    op.drop_column("users", "full_name")
