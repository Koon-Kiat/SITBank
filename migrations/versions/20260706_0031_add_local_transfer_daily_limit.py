"""Add local transfer daily limit.

Revision ID: 20260706_0031
Revises: 20260705_0030
Create Date: 2026-07-06 00:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260706_0031"
down_revision = "20260705_0030"
branch_labels = None
depends_on = None


_LOCAL_TRANSFER_LIMIT_CHECK = (
    "local_transfer_daily_limit >= 100.00 AND local_transfer_daily_limit <= 10000.00"
)


def upgrade() -> None:
    if op.get_context().as_sql:
        op.add_column(
            "users",
            sa.Column(
                "local_transfer_daily_limit",
                sa.Numeric(precision=10, scale=2),
                nullable=False,
                server_default="500.00",
            ),
        )
        if op.get_context().dialect.name == "postgresql":
            op.create_check_constraint(
                "ck_users_local_transfer_daily_limit_bounds", "users", _LOCAL_TRANSFER_LIMIT_CHECK
            )
        else:
            op.execute(
                "-- SQLite offline SQL cannot add the Local Transfer limit check constraint portably."
            )
        return

    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(
            sa.Column(
                "local_transfer_daily_limit",
                sa.Numeric(precision=10, scale=2),
                nullable=False,
                server_default="500.00",
            )
        )
        batch_op.create_check_constraint(
            "ck_users_local_transfer_daily_limit_bounds", _LOCAL_TRANSFER_LIMIT_CHECK
        )


def downgrade() -> None:
    if op.get_context().as_sql:
        if op.get_context().dialect.name == "postgresql":
            op.drop_constraint("ck_users_local_transfer_daily_limit_bounds", "users", type_="check")
        else:
            op.execute(
                "-- SQLite offline SQL cannot drop the Local Transfer limit check constraint portably."
            )
        op.drop_column("users", "local_transfer_daily_limit")
        return

    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_constraint("ck_users_local_transfer_daily_limit_bounds", type_="check")
        batch_op.drop_column("local_transfer_daily_limit")
