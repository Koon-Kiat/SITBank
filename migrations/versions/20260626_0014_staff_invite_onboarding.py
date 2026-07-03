"""Add staff invite onboarding and identity separation tables.

Revision ID: 20260626_0014
Revises: 20260625_0013
Create Date: 2026-06-26 00:14:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260626_0014"
down_revision = "20260625_0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("account_type", sa.String(length=32), nullable=False, server_default="customer"),
    )
    op.add_column(
        "users",
        sa.Column("account_status", sa.String(length=32), nullable=False, server_default="active"),
    )
    op.add_column(
        "users",
        sa.Column("staff_personal_email", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("workplace_email_verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    if op.get_context().dialect.name != "sqlite":
        op.alter_column("users", "account_number", existing_type=sa.String(12), nullable=True)
        op.create_check_constraint(
            "ck_users_account_type",
            "users",
            "account_type IN ('customer', 'staff', 'admin', 'root_admin')",
        )
        op.create_check_constraint(
            "ck_users_account_status",
            "users",
            "account_status IN ('active', 'setup_pending', 'revoked', 'locked')",
        )
    op.create_index("ix_users_account_type", "users", ["account_type"])
    op.create_index("ix_users_account_status", "users", ["account_status"])

    op.create_table(
        "staff_invites",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
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
    op.create_index("ix_staff_invites_created_at", "staff_invites", ["created_at"])
    op.create_index("ix_staff_invites_created_by_user_id", "staff_invites", ["created_by_user_id"])
    op.create_index("ix_staff_invites_expires_at", "staff_invites", ["expires_at"])
    op.create_index("ix_staff_invites_revoked_by_user_id", "staff_invites", ["revoked_by_user_id"])
    op.create_index("ix_staff_invites_setup_user_id", "staff_invites", ["setup_user_id"])
    op.create_index("ix_staff_invites_status", "staff_invites", ["status"])
    op.create_index("ix_staff_invites_token_hash", "staff_invites", ["token_hash"], unique=True)
    op.create_index("ix_staff_invites_used_by_user_id", "staff_invites", ["used_by_user_id"])
    op.create_index("ix_staff_invites_workplace_email_normalized", "staff_invites", ["workplace_email_normalized"])

    op.create_table(
        "person_identity_links",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("staff_user_id", sa.Integer(), nullable=False),
        sa.Column("customer_user_id", sa.Integer(), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("notes", sa.String(length=512), nullable=False),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["customer_user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["staff_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "staff_user_id",
            "customer_user_id",
            name="uq_person_identity_links_staff_customer",
        ),
    )
    op.create_index("ix_person_identity_links_created_by_user_id", "person_identity_links", ["created_by_user_id"])
    op.create_index("ix_person_identity_links_customer_user_id", "person_identity_links", ["customer_user_id"])
    op.create_index("ix_person_identity_links_revoked_at", "person_identity_links", ["revoked_at"])
    op.create_index("ix_person_identity_links_staff_user_id", "person_identity_links", ["staff_user_id"])


def downgrade() -> None:
    op.drop_index("ix_person_identity_links_staff_user_id", table_name="person_identity_links")
    op.drop_index("ix_person_identity_links_revoked_at", table_name="person_identity_links")
    op.drop_index("ix_person_identity_links_customer_user_id", table_name="person_identity_links")
    op.drop_index("ix_person_identity_links_created_by_user_id", table_name="person_identity_links")
    op.drop_table("person_identity_links")

    op.drop_index("ix_staff_invites_workplace_email_normalized", table_name="staff_invites")
    op.drop_index("ix_staff_invites_used_by_user_id", table_name="staff_invites")
    op.drop_index("ix_staff_invites_token_hash", table_name="staff_invites")
    op.drop_index("ix_staff_invites_status", table_name="staff_invites")
    op.drop_index("ix_staff_invites_setup_user_id", table_name="staff_invites")
    op.drop_index("ix_staff_invites_revoked_by_user_id", table_name="staff_invites")
    op.drop_index("ix_staff_invites_expires_at", table_name="staff_invites")
    op.drop_index("ix_staff_invites_created_by_user_id", table_name="staff_invites")
    op.drop_index("ix_staff_invites_created_at", table_name="staff_invites")
    op.drop_table("staff_invites")

    op.drop_index("ix_users_account_status", table_name="users")
    op.drop_index("ix_users_account_type", table_name="users")
    dialect = op.get_context().dialect.name
    if dialect != "sqlite":
        op.drop_constraint("ck_users_account_status", "users", type_="check")
        op.drop_constraint("ck_users_account_type", "users", type_="check")
        op.alter_column("users", "account_number", existing_type=sa.String(12), nullable=False)
    op.drop_column("users", "workplace_email_verified_at")
    op.drop_column("users", "staff_personal_email")
    op.drop_column("users", "account_status")
    op.drop_column("users", "account_type")
