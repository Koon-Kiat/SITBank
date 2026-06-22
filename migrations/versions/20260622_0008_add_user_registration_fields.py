"""Add full_name, phone_number, and account_number to users table.

Revision ID: 20260622_0008
Revises: 20260621_0007
Create Date: 2026-06-22 00:00:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


revision = "20260622_0008"
down_revision = "20260621_0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    dialect = op.get_context().dialect.name

    if dialect == "postgresql":
        op.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(128)"))
        op.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_number VARCHAR(8)"))
        op.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS account_number VARCHAR(9)"))
    else:
        op.add_column("users", sa.Column("full_name", sa.String(128), nullable=True))
        op.add_column("users", sa.Column("phone_number", sa.String(8), nullable=True))
        op.add_column("users", sa.Column("account_number", sa.String(9), nullable=True))

    op.execute(text("UPDATE users SET full_name = '' WHERE full_name IS NULL"))
    op.execute(text("UPDATE users SET phone_number = '' WHERE phone_number IS NULL"))

    if dialect == "postgresql":
        op.execute(text(
            "UPDATE users SET account_number = '012' || lpad((floor(random() * 1000000))::text, 6, '0') "
            "WHERE account_number IS NULL"
        ))
    else:
        op.execute(text(
            "UPDATE users SET account_number = '012' || printf('%06d', abs(random()) % 1000000) "
            "WHERE account_number IS NULL"
        ))

    if dialect != "sqlite":
        op.alter_column("users", "full_name", existing_type=sa.String(128), nullable=False)
        op.alter_column("users", "phone_number", existing_type=sa.String(8), nullable=False)
        op.alter_column("users", "account_number", existing_type=sa.String(9), nullable=False)

    op.create_index("ix_users_phone_number", "users", ["phone_number"], unique=True, if_not_exists=True)
    op.create_index("ix_users_account_number", "users", ["account_number"], unique=True, if_not_exists=True)


def downgrade() -> None:
    op.drop_index("ix_users_account_number", table_name="users")
    op.drop_index("ix_users_phone_number", table_name="users")
    op.drop_column("users", "account_number")
    op.drop_column("users", "phone_number")
    op.drop_column("users", "full_name")
