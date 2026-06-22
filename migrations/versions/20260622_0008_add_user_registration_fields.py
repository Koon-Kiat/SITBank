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

    op.execute(text("UPDATE users SET full_name = username WHERE full_name IS NULL OR full_name = ''"))

    if dialect == "postgresql":
        op.execute(
            text(
                """
                WITH numbered AS (
                    SELECT id, row_number() OVER (ORDER BY id) AS row_index
                    FROM users
                    WHERE phone_number IS NULL OR phone_number = ''
                )
                UPDATE users
                SET phone_number = '9' || lpad(numbered.row_index::text, 7, '0')
                FROM numbered
                WHERE users.id = numbered.id
                """
            )
        )
        op.execute(
            text(
                """
                WITH numbered AS (
                    SELECT id, row_number() OVER (ORDER BY id) AS row_index
                    FROM users
                    WHERE account_number IS NULL OR account_number = ''
                )
                UPDATE users
                SET account_number = '012' || lpad(numbered.row_index::text, 6, '0')
                FROM numbered
                WHERE users.id = numbered.id
                """
            )
        )
    else:
        op.execute(
            text(
                """
                WITH numbered AS (
                    SELECT id, row_number() OVER (ORDER BY id) AS row_index
                    FROM users
                    WHERE phone_number IS NULL OR phone_number = ''
                )
                UPDATE users
                SET phone_number = (
                    SELECT '9' || printf('%07d', numbered.row_index)
                    FROM numbered
                    WHERE numbered.id = users.id
                )
                WHERE id IN (SELECT id FROM numbered)
                """
            )
        )
        op.execute(
            text(
                """
                WITH numbered AS (
                    SELECT id, row_number() OVER (ORDER BY id) AS row_index
                    FROM users
                    WHERE account_number IS NULL OR account_number = ''
                )
                UPDATE users
                SET account_number = (
                    SELECT '012' || printf('%06d', numbered.row_index)
                    FROM numbered
                    WHERE numbered.id = users.id
                )
                WHERE id IN (SELECT id FROM numbered)
                """
            )
        )

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
