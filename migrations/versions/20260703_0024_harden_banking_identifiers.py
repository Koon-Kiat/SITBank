"""Enforce twelve-digit banking account identifiers.

Revision ID: 20260703_0024
Revises: 20260703_0023
Create Date: 2026-07-03 18:00:00
"""

from alembic import op


revision = "20260703_0024"
down_revision = "20260703_0023"
branch_labels = None
depends_on = None

_DIGIT_CHECK = " AND ".join(
    f"substr(account_number, {position}, 1) BETWEEN '0' AND '9'"
    for position in range(1, 13)
)


def upgrade() -> None:
    if op.get_context().as_sql:
        op.execute(
            "ALTER TABLE users ADD CONSTRAINT ck_users_account_number_format "
            f"CHECK (account_number IS NULL OR (length(account_number) = 12 AND {_DIGIT_CHECK}))"
        )
        op.execute(
            "ALTER TABLE payees ADD CONSTRAINT ck_payees_account_number_format "
            f"CHECK (length(account_number) = 12 AND {_DIGIT_CHECK})"
        )
        return

    with op.batch_alter_table("users") as batch_op:
        batch_op.create_check_constraint(
            "ck_users_account_number_format",
            f"account_number IS NULL OR (length(account_number) = 12 AND {_DIGIT_CHECK})",
        )
    with op.batch_alter_table("payees") as batch_op:
        batch_op.create_check_constraint(
            "ck_payees_account_number_format",
            f"length(account_number) = 12 AND {_DIGIT_CHECK}",
        )


def downgrade() -> None:
    if op.get_context().as_sql:
        op.execute("ALTER TABLE payees DROP CONSTRAINT ck_payees_account_number_format")
        op.execute("ALTER TABLE users DROP CONSTRAINT ck_users_account_number_format")
        return

    with op.batch_alter_table("payees") as batch_op:
        batch_op.drop_constraint("ck_payees_account_number_format", type_="check")
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_constraint("ck_users_account_number_format", type_="check")
