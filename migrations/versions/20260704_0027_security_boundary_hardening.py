"""Harden PayUp limits, invite verification lockouts, and recovery codes.

Revision ID: 20260704_0027
Revises: 20260704_0026
Create Date: 2026-07-04 18:00:00
"""

import sqlalchemy as sa
from alembic import op


revision = "20260704_0027"
down_revision = "20260704_0026"
branch_labels = None
depends_on = None


_PAYUP_LIMIT_CHECK = "payup_daily_limit >= 100.00 AND payup_daily_limit <= 10000.00"


def upgrade() -> None:
    if op.get_context().as_sql:
        op.add_column(
            "staff_invites",
            sa.Column("acceptance_verify_count", sa.Integer(), nullable=False, server_default="0"),
        )
        op.add_column(
            "staff_invites",
            sa.Column("acceptance_verify_locked_at", sa.DateTime(timezone=True), nullable=True),
        )
        if op.get_context().dialect.name == "postgresql":
            op.create_check_constraint("ck_users_payup_daily_limit_bounds", "users", _PAYUP_LIMIT_CHECK)
        else:
            op.execute("-- SQLite offline SQL cannot add the PayUp limit check constraint portably.")
        op.execute(
            "UPDATE recovery_codes SET used_at = CURRENT_TIMESTAMP "
            "WHERE hmac_version < 2 AND used_at IS NULL"
        )
        return

    with op.batch_alter_table("staff_invites") as batch_op:
        batch_op.add_column(sa.Column("acceptance_verify_count", sa.Integer(), nullable=False, server_default="0"))
        batch_op.add_column(sa.Column("acceptance_verify_locked_at", sa.DateTime(timezone=True), nullable=True))
    with op.batch_alter_table("users") as batch_op:
        batch_op.create_check_constraint("ck_users_payup_daily_limit_bounds", _PAYUP_LIMIT_CHECK)
    op.execute(
        "UPDATE recovery_codes SET used_at = CURRENT_TIMESTAMP "
        "WHERE hmac_version < 2 AND used_at IS NULL"
    )


def downgrade() -> None:
    if op.get_context().as_sql:
        if op.get_context().dialect.name == "postgresql":
            op.drop_constraint("ck_users_payup_daily_limit_bounds", "users", type_="check")
            op.drop_column("staff_invites", "acceptance_verify_locked_at")
            op.drop_column("staff_invites", "acceptance_verify_count")
        else:
            op.execute("-- SQLite offline SQL cannot drop invite acceptance verification columns portably.")
        return

    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_constraint("ck_users_payup_daily_limit_bounds", type_="check")
    with op.batch_alter_table("staff_invites") as batch_op:
        batch_op.drop_column("acceptance_verify_locked_at")
        batch_op.drop_column("acceptance_verify_count")
