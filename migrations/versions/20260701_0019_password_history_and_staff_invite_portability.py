"""Add password history and portable staff invite nullability.

Revision ID: 20260701_0019
Revises: 20260630_0018
Create Date: 2026-07-01 00:19:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260701_0019"
down_revision = "20260630_0018"
branch_labels = None
depends_on = None


def _staff_invites_table() -> sa.Table:
    metadata = sa.MetaData()
    table = sa.Table(
        "staff_invites",
        metadata,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("personal_email_normalized", sa.String(length=255), nullable=False),
        sa.Column("workplace_email_normalized", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), nullable=False),
        sa.Column("setup_user_id", sa.Integer(), nullable=True),
        sa.Column("used_by_user_id", sa.Integer(), nullable=True),
        sa.Column("revoked_by_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("workplace_verification_code_hmac", sa.String(length=64), nullable=True),
        sa.Column("workplace_verification_sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("workplace_verification_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("workplace_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["revoked_by_user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["setup_user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["used_by_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
        sa.CheckConstraint("role IN ('staff', 'admin')", name="ck_staff_invites_role"),
        sa.CheckConstraint(
            "status IN ('pending', 'totp_pending', 'accepted', 'revoked', 'expired')",
            name="ck_staff_invites_status",
        ),
    )
    sa.Index("ix_staff_invites_created_at", table.c.created_at)
    sa.Index("ix_staff_invites_created_by_user_id", table.c.created_by_user_id)
    sa.Index("ix_staff_invites_expires_at", table.c.expires_at)
    sa.Index("ix_staff_invites_personal_email_normalized", table.c.personal_email_normalized)
    sa.Index("ix_staff_invites_revoked_by_user_id", table.c.revoked_by_user_id)
    sa.Index("ix_staff_invites_setup_user_id", table.c.setup_user_id)
    sa.Index("ix_staff_invites_status", table.c.status)
    sa.Index("ix_staff_invites_token_hash", table.c.token_hash, unique=True)
    sa.Index("ix_staff_invites_used_by_user_id", table.c.used_by_user_id)
    sa.Index("ix_staff_invites_workplace_email_normalized", table.c.workplace_email_normalized)
    return table


def upgrade() -> None:
    with op.batch_alter_table("staff_invites", copy_from=_staff_invites_table()) as batch_op:
        batch_op.alter_column(
            "personal_email_normalized",
            existing_type=sa.String(length=255),
            nullable=True,
        )

    op.add_column("users", sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "users",
        sa.Column(
            "force_password_change",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        )
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

    op.execute(
        sa.text(
            "UPDATE users SET password_changed_at = created_at "
            "WHERE password_changed_at IS NULL"
        )
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

    # Do not force staff_invites.personal_email_normalized back to NOT NULL:
    # existing workplace-only privileged invites may legitimately have no
    # personal email value.
    return
