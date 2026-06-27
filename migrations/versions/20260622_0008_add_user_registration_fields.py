"""Add full_name, phone_number, and account_number to users table.

Revision ID: 20260622_0008
Revises: 20260621_0007
Create Date: 2026-06-22 00:00:00
"""

import secrets

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


revision = "20260622_0008"
down_revision = "20260621_0007"
branch_labels = None
depends_on = None


def _generate_account_number(existing: set[str]) -> str:
    for _attempt in range(100):
        candidate = "012" + "".join(str(secrets.randbelow(10)) for _ in range(6))
        if candidate not in existing:
            existing.add(candidate)
            return candidate
    raise RuntimeError("Could not generate a unique account number for existing users")


def _backfill_account_numbers() -> None:
    if op.get_context().as_sql:
        op.execute(
            "-- Existing-user account numbers are backfilled during online "
            "migration with Python secrets; fresh offline SQL has no rows to backfill."
        )
        return

    bind = op.get_bind()
    existing = {
        row[0]
        for row in bind.execute(
            text("SELECT account_number FROM users WHERE account_number IS NOT NULL AND account_number != ''")
        )
    }
    rows = bind.execute(
        text("SELECT id FROM users WHERE account_number IS NULL OR account_number = '' ORDER BY id")
    ).fetchall()
    for row in rows:
        bind.execute(
            text("UPDATE users SET account_number = :account_number WHERE id = :user_id"),
            {"account_number": _generate_account_number(existing), "user_id": row[0]},
        )


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
    op.execute(text("UPDATE users SET phone_number = NULL WHERE phone_number = ''"))
    _backfill_account_numbers()

    if dialect != "sqlite":
        op.alter_column("users", "full_name", existing_type=sa.String(128), nullable=False)
        op.alter_column("users", "account_number", existing_type=sa.String(9), nullable=False)

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
