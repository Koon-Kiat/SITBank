"""Add DB-backed security state tables.

Revision ID: 20260625_0013
Revises: 20260625_0012
Create Date: 2026-06-25 19:30:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260625_0013"
down_revision = "20260625_0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "server_side_sessions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("component", sa.String(length=32), nullable=False),
        sa.Column("session_lookup_hash", sa.String(length=64), nullable=False),
        sa.Column("session_ref", sa.String(length=32), nullable=True),
        sa.Column("payload", sa.LargeBinary(), nullable=True),
        sa.Column("payload_format", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_reason", sa.String(length=32), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=False),
        sa.Column("user_agent", sa.String(length=256), nullable=False),
        sa.Column("risk_fingerprint", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "component",
            "session_lookup_hash",
            name="uq_server_side_sessions_component_lookup_hash",
        ),
    )
    op.create_index(
        "ix_server_side_sessions_component_user_active",
        "server_side_sessions",
        ["component", "user_id", "revoked_at", "expires_at"],
    )
    op.create_index("ix_server_side_sessions_expires_at", "server_side_sessions", ["expires_at"])
    op.create_index("ix_server_side_sessions_last_activity_at", "server_side_sessions", ["last_activity_at"])
    op.create_index("ix_server_side_sessions_session_ref", "server_side_sessions", ["session_ref"])
    op.create_index("ix_server_side_sessions_user_id", "server_side_sessions", ["user_id"])

    op.create_table(
        "auth_attempt_counters",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scope", sa.String(length=80), nullable=False),
        sa.Column("principal_hash", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("ip_hash", sa.String(length=64), nullable=True),
        sa.Column("failure_count", sa.Integer(), nullable=False),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_failed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scope", "principal_hash", name="uq_auth_attempt_counters_scope_principal"),
    )
    op.create_index("ix_auth_attempt_counters_ip_hash", "auth_attempt_counters", ["ip_hash"])
    op.create_index("ix_auth_attempt_counters_locked_until", "auth_attempt_counters", ["locked_until"])
    op.create_index("ix_auth_attempt_counters_user_id", "auth_attempt_counters", ["user_id"])
    op.create_index("ix_auth_attempt_counters_window_expires_at", "auth_attempt_counters", ["window_expires_at"])

    op.create_table(
        "totp_replay_records",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("scope", sa.String(length=80), nullable=False),
        sa.Column("time_step", sa.Integer(), nullable=False),
        sa.Column("code_digest", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "user_id",
            "scope",
            "time_step",
            "code_digest",
            name="uq_totp_replay_records_user_scope_step_digest",
        ),
    )
    op.create_index("ix_totp_replay_records_expires_at", "totp_replay_records", ["expires_at"])
    op.create_index("ix_totp_replay_records_user_id", "totp_replay_records", ["user_id"])

    op.create_table(
        "registration_otp_challenges",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("session_binding_hash", sa.String(length=64), nullable=False),
        sa.Column("email_hash", sa.String(length=64), nullable=False),
        sa.Column("otp_hmac", sa.String(length=64), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("resend_available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "session_binding_hash",
            "email_hash",
            name="uq_registration_otp_challenges_session_email",
        ),
    )
    op.create_index("ix_registration_otp_challenges_expires_at", "registration_otp_challenges", ["expires_at"])
    op.create_index("ix_registration_otp_challenges_used_at", "registration_otp_challenges", ["used_at"])

    op.create_table(
        "password_reset_transactions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("transaction_lookup_hash", sa.String(length=64), nullable=False),
        sa.Column("token_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("purpose", sa.String(length=40), nullable=False),
        sa.Column("mfa_required", sa.String(length=40), nullable=False),
        sa.Column("available_mfa_methods_json", sa.JSON(), nullable=False),
        sa.Column("preferred_mfa_method", sa.String(length=40), nullable=True),
        sa.Column("default_mfa_method", sa.String(length=40), nullable=True),
        sa.Column("mfa_verified", sa.Boolean(), nullable=False),
        sa.Column("recovery_code_verified", sa.Boolean(), nullable=False),
        sa.Column("no_mfa_user", sa.Boolean(), nullable=False),
        sa.Column("failure_count", sa.Integer(), nullable=False),
        sa.Column("last_failure_reason", sa.String(length=80), nullable=True),
        sa.Column("mfa_verified_at", sa.Integer(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["token_id"], ["password_reset_tokens.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("transaction_lookup_hash"),
    )
    op.create_index("ix_password_reset_transactions_expires_at", "password_reset_transactions", ["expires_at"])
    op.create_index("ix_password_reset_transactions_token_id", "password_reset_transactions", ["token_id"])
    op.create_index(
        "ix_password_reset_transactions_user_expires_at",
        "password_reset_transactions",
        ["user_id", "expires_at"],
    )
    op.create_index("ix_password_reset_transactions_user_id", "password_reset_transactions", ["user_id"])

    op.create_table(
        "security_alert_dedupe",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("dedupe_key_hash", sa.String(length=64), nullable=False),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("dedupe_key_hash"),
    )
    op.create_index("ix_security_alert_dedupe_expires_at", "security_alert_dedupe", ["expires_at"])

    op.create_table(
        "security_circuit_breakers",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("service_name", sa.String(length=80), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("failure_count", sa.Integer(), nullable=False),
        sa.Column("opened_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_failure_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("service_name"),
    )
    op.create_index("ix_security_circuit_breakers_opened_until", "security_circuit_breakers", ["opened_until"])


def downgrade() -> None:
    op.drop_index("ix_security_circuit_breakers_opened_until", table_name="security_circuit_breakers")
    op.drop_table("security_circuit_breakers")
    op.drop_index("ix_security_alert_dedupe_expires_at", table_name="security_alert_dedupe")
    op.drop_table("security_alert_dedupe")
    op.drop_index("ix_password_reset_transactions_user_id", table_name="password_reset_transactions")
    op.drop_index("ix_password_reset_transactions_user_expires_at", table_name="password_reset_transactions")
    op.drop_index("ix_password_reset_transactions_token_id", table_name="password_reset_transactions")
    op.drop_index("ix_password_reset_transactions_expires_at", table_name="password_reset_transactions")
    op.drop_table("password_reset_transactions")
    op.drop_index("ix_registration_otp_challenges_used_at", table_name="registration_otp_challenges")
    op.drop_index("ix_registration_otp_challenges_expires_at", table_name="registration_otp_challenges")
    op.drop_table("registration_otp_challenges")
    op.drop_index("ix_totp_replay_records_user_id", table_name="totp_replay_records")
    op.drop_index("ix_totp_replay_records_expires_at", table_name="totp_replay_records")
    op.drop_table("totp_replay_records")
    op.drop_index("ix_auth_attempt_counters_window_expires_at", table_name="auth_attempt_counters")
    op.drop_index("ix_auth_attempt_counters_user_id", table_name="auth_attempt_counters")
    op.drop_index("ix_auth_attempt_counters_locked_until", table_name="auth_attempt_counters")
    op.drop_index("ix_auth_attempt_counters_ip_hash", table_name="auth_attempt_counters")
    op.drop_table("auth_attempt_counters")
    op.drop_index("ix_server_side_sessions_user_id", table_name="server_side_sessions")
    op.drop_index("ix_server_side_sessions_session_ref", table_name="server_side_sessions")
    op.drop_index("ix_server_side_sessions_last_activity_at", table_name="server_side_sessions")
    op.drop_index("ix_server_side_sessions_expires_at", table_name="server_side_sessions")
    op.drop_index("ix_server_side_sessions_component_user_active", table_name="server_side_sessions")
    op.drop_table("server_side_sessions")
