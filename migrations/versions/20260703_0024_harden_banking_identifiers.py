"""Harden banking account identifier length.

Revision ID: 20260703_0024
Revises: 20260703_0023
Create Date: 2026-07-03 18:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260703_0024"
down_revision = "20260703_0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if op.get_context().as_sql:
        op.execute("ALTER TABLE users ALTER COLUMN account_number TYPE VARCHAR(12)")
        op.execute("ALTER TABLE payees ALTER COLUMN account_number TYPE VARCHAR(12)")
        return

    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column(
            "account_number",
            existing_type=sa.String(length=9),
            type_=sa.String(length=12),
            existing_nullable=True,
        )
    with op.batch_alter_table("payees") as batch_op:
        batch_op.alter_column(
            "account_number",
            existing_type=sa.String(length=9),
            type_=sa.String(length=12),
            existing_nullable=False,
        )


def downgrade() -> None:
    if op.get_context().as_sql:
        op.execute(
            sa.text(
                "-- Downgrade requires no users/payees with 12-digit account numbers; "
                "otherwise it must be handled manually to avoid identifier corruption."
            )
        )
        op.execute("ALTER TABLE payees ALTER COLUMN account_number TYPE VARCHAR(9)")
        op.execute("ALTER TABLE users ALTER COLUMN account_number TYPE VARCHAR(9)")
        return
    else:
        connection = op.get_bind()
        users = sa.table("users", sa.column("account_number", sa.String()))
        payees = sa.table("payees", sa.column("account_number", sa.String()))
        user_count = connection.execute(
            sa.select(sa.func.count()).select_from(users).where(
                sa.func.length(users.c.account_number) > 9
            )
        ).scalar_one()
        payee_count = connection.execute(
            sa.select(sa.func.count()).select_from(payees).where(
                sa.func.length(payees.c.account_number) > 9
            )
        ).scalar_one()
        if int(user_count or 0) or int(payee_count or 0):
            raise RuntimeError(
                "Cannot safely downgrade account_number length while 12-digit account numbers exist"
            )
    with op.batch_alter_table("payees") as batch_op:
        batch_op.alter_column(
            "account_number",
            existing_type=sa.String(length=12),
            type_=sa.String(length=9),
            existing_nullable=False,
        )
    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column(
            "account_number",
            existing_type=sa.String(length=12),
            type_=sa.String(length=9),
            existing_nullable=True,
        )
