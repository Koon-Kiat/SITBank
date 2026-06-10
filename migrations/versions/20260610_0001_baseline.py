"""Create the initial authentication and audit schema.

Revision ID: 20260610_0001
Revises:
Create Date: 2026-06-10 00:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260610_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("mfa_secret_ciphertext", sa.LargeBinary(), nullable=True),
        sa.Column("mfa_secret_nonce", sa.LargeBinary(length=12), nullable=True),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False),
        sa.Column("is_frozen", sa.Boolean(), nullable=False),
        sa.Column("failed_login_count", sa.Integer(), nullable=False),
        sa.Column("security_locked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("security_lock_reason", sa.String(length=160), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_users_email_lower",
        "users",
        [sa.text("lower(email)")],
        unique=True,
    )
    op.create_index(
        "ix_users_username_lower",
        "users",
        [sa.text("lower(username)")],
        unique=True,
    )

    op.create_table(
        "webauthn_credentials",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("credential_id", sa.LargeBinary(), nullable=False),
        sa.Column("credential_public_key", sa.LargeBinary(), nullable=False),
        sa.Column("sign_count", sa.Integer(), nullable=False),
        sa.Column("label", sa.String(length=80), nullable=False),
        sa.Column("aaguid", sa.String(length=36), nullable=False),
        sa.Column("attestation_format", sa.String(length=32), nullable=False),
        sa.Column("transports", sa.JSON(), nullable=False),
        sa.Column("credential_device_type", sa.String(length=32), nullable=False),
        sa.Column("credential_backed_up", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("credential_id", name="uq_webauthn_credentials_credential_id"),
    )
    op.create_index(
        "ix_webauthn_credentials_aaguid",
        "webauthn_credentials",
        ["aaguid"],
        unique=False,
    )
    op.create_index(
        "ix_webauthn_credentials_user_id",
        "webauthn_credentials",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "ix_webauthn_credentials_user_label_lower",
        "webauthn_credentials",
        ["user_id", sa.text("lower(label)")],
        unique=True,
    )

    op.create_table(
        "security_audit_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column("outcome", sa.String(length=24), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=False),
        sa.Column("user_agent", sa.String(length=256), nullable=False),
        sa.Column("correlation_id", sa.String(length=36), nullable=False),
        sa.Column("session_ref", sa.String(length=32), nullable=True),
        sa.Column("event_metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_security_audit_events_correlation_id",
        "security_audit_events",
        ["correlation_id"],
        unique=False,
    )
    op.create_index(
        "ix_security_audit_events_created_at",
        "security_audit_events",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        "ix_security_audit_events_event_type",
        "security_audit_events",
        ["event_type"],
        unique=False,
    )
    op.create_index(
        "ix_security_audit_events_outcome",
        "security_audit_events",
        ["outcome"],
        unique=False,
    )
    op.create_index(
        "ix_security_audit_events_user_id",
        "security_audit_events",
        ["user_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_security_audit_events_user_id", table_name="security_audit_events")
    op.drop_index("ix_security_audit_events_outcome", table_name="security_audit_events")
    op.drop_index("ix_security_audit_events_event_type", table_name="security_audit_events")
    op.drop_index("ix_security_audit_events_created_at", table_name="security_audit_events")
    op.drop_index("ix_security_audit_events_correlation_id", table_name="security_audit_events")
    op.drop_table("security_audit_events")

    op.drop_index(
        "ix_webauthn_credentials_user_label_lower",
        table_name="webauthn_credentials",
    )
    op.drop_index("ix_webauthn_credentials_user_id", table_name="webauthn_credentials")
    op.drop_index("ix_webauthn_credentials_aaguid", table_name="webauthn_credentials")
    op.drop_table("webauthn_credentials")

    op.drop_index("ix_users_username_lower", table_name="users")
    op.drop_index("ix_users_email_lower", table_name="users")
    op.drop_table("users")

