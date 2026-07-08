from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

from sqlalchemy import Index, func

from app.banking.limits import (
    LOCAL_TRANSFER_DAILY_LIMIT_DEFAULT,
    LOCAL_TRANSFER_DAILY_LIMIT_MAX,
    LOCAL_TRANSFER_DAILY_LIMIT_MIN,
    PAYUP_DAILY_LIMIT_DEFAULT,
    PAYUP_DAILY_LIMIT_MAX,
    PAYUP_DAILY_LIMIT_MIN,
)
from app.banking.schemas import MAX_TRANSACTION_AMOUNT, MIN_TRANSACTION_AMOUNT

from .extensions import db

_USER_ID_FOREIGN_KEY = "users.id"
_CASCADE_DELETE_ORPHAN = "all, delete-orphan"


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    registration_email_canonical = db.Column(db.String(255), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    account_type = db.Column(db.String(32), nullable=False, default="customer", index=True)
    account_status = db.Column(db.String(32), nullable=False, default="active", index=True)
    full_name = db.Column(db.String(128), nullable=False)
    phone_number = db.Column(db.String(8), nullable=True)
    payup_nickname = db.Column(db.String(128), nullable=True)
    account_number = db.Column(db.String(12), nullable=True)
    staff_personal_email = db.Column(db.String(255), nullable=True)
    workplace_email_verified_at = db.Column(db.DateTime(timezone=True), nullable=True)
    password_changed_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    force_password_change = db.Column(db.Boolean, nullable=False, default=False)
    force_password_change_reason = db.Column(db.String(80), nullable=True)
    force_password_change_at = db.Column(db.DateTime(timezone=True), nullable=True)

    mfa_secret_ciphertext = db.Column(db.LargeBinary, nullable=True)
    mfa_secret_nonce = db.Column(db.LargeBinary(12), nullable=True)
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    mfa_pending_started_at = db.Column(db.DateTime(timezone=True), nullable=True)
    mfa_pending_session_hash = db.Column(db.String(64), nullable=True)
    balance = db.Column(
        db.Numeric(12, 2),
        nullable=False,
        default=Decimal("0.00"),
        server_default="0.00",
    )
    payup_daily_limit = db.Column(
        db.Numeric(10, 2),
        nullable=False,
        default=PAYUP_DAILY_LIMIT_DEFAULT,
        server_default=str(PAYUP_DAILY_LIMIT_DEFAULT),
    )
    payup_enabled = db.Column(
        db.Boolean,
        nullable=False,
        default=True,
        server_default=db.true(),
    )
    local_transfer_daily_limit = db.Column(
        db.Numeric(10, 2),
        nullable=False,
        default=LOCAL_TRANSFER_DAILY_LIMIT_DEFAULT,
        server_default=str(LOCAL_TRANSFER_DAILY_LIMIT_DEFAULT),
    )

    is_frozen = db.Column(db.Boolean, nullable=False, default=False)
    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    security_locked_at = db.Column(db.DateTime(timezone=True), nullable=True)
    security_lock_reason = db.Column(db.String(160), nullable=True)

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    last_login_at = db.Column(db.DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_users_username_lower", func.lower(username), unique=True),
        Index("ix_users_email_lower", func.lower(email), unique=True),
        Index(
            "ix_users_registration_email_canonical",
            "registration_email_canonical",
            unique=True,
            postgresql_where=registration_email_canonical.isnot(None),
            sqlite_where=registration_email_canonical.isnot(None),
        ),
        Index(
            "ix_users_phone_number",
            "phone_number",
            unique=True,
            postgresql_where=phone_number.isnot(None),
            sqlite_where=phone_number.isnot(None),
        ),
        Index("ix_users_account_number", "account_number", unique=True),
        db.CheckConstraint(
            "account_type IN ('customer', 'staff', 'admin', 'root_admin')",
            name="ck_users_account_type",
        ),
        db.CheckConstraint(
            "account_status IN ('active', 'setup_pending', 'revoked', 'locked')",
            name="ck_users_account_status",
        ),
        db.CheckConstraint("balance >= 0", name="ck_users_balance_non_negative"),
        db.CheckConstraint(
            (
                f"payup_daily_limit >= {PAYUP_DAILY_LIMIT_MIN} "
                f"AND payup_daily_limit <= {PAYUP_DAILY_LIMIT_MAX}"
            ),
            name="ck_users_payup_daily_limit_bounds",
        ),
        db.CheckConstraint(
            (
                f"local_transfer_daily_limit >= {LOCAL_TRANSFER_DAILY_LIMIT_MIN} "
                f"AND local_transfer_daily_limit <= {LOCAL_TRANSFER_DAILY_LIMIT_MAX}"
            ),
            name="ck_users_local_transfer_daily_limit_bounds",
        ),
        db.CheckConstraint(
            (
                "account_number IS NULL OR (length(account_number) = 12 AND "
                + " AND ".join(
                    f"substr(account_number, {position}, 1) BETWEEN '0' AND '9'"
                    for position in range(1, 13)
                )
                + ")"
            ),
            name="ck_users_account_number_format",
        ),
    )

    def __repr__(self) -> str:
        return f"<User id={self.id!r} username={self.username!r}>"


class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_tokens"

    id = db.Column(db.Integer, primary_key=True)
    selector = db.Column(db.String(64), nullable=False, unique=True, index=True)
    verifier_hmac = db.Column(db.String(64), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=False, index=True)
    purpose = db.Column(db.String(40), nullable=False, default="password_reset")
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    used_at = db.Column(db.DateTime(timezone=True), nullable=True)
    exchanged_at = db.Column(db.DateTime(timezone=True), nullable=True)
    requested_ip = db.Column(db.String(64), nullable=False, default="")
    requested_user_agent = db.Column(db.String(256), nullable=False, default="")

    user = db.relationship("User", backref="password_reset_tokens")


class RecoveryCode(db.Model):
    __tablename__ = "recovery_codes"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=False, index=True)
    code_hmac = db.Column(db.String(64), nullable=False, unique=True, index=True)
    hmac_version = db.Column(db.Integer, nullable=False, default=2, server_default="2")
    purpose = db.Column(db.String(40), nullable=False, default="totp_recovery")
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    used_at = db.Column(db.DateTime(timezone=True), nullable=True)

    user = db.relationship("User", backref="recovery_codes")


class PasswordHistory(db.Model):
    __tablename__ = "password_history"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    user = db.relationship(
        "User",
        backref=db.backref(
            "password_history",
            cascade=_CASCADE_DELETE_ORPHAN,
            lazy="selectin",
        ),
    )

    __table_args__ = (
        Index("ix_password_history_user_created_at", "user_id", "created_at"),
    )


class ManualRecoveryRequest(db.Model):
    __tablename__ = "manual_recovery_requests"

    id = db.Column(db.Integer, primary_key=True)
    identifier_ref = db.Column(db.String(64), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=True, index=True)
    status = db.Column(db.String(32), nullable=False, default="pending", index=True)
    requested_ip = db.Column(db.String(64), nullable=False, default="")
    requested_user_agent = db.Column(db.String(256), nullable=False, default="")
    request_count = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    last_submitted_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    status_changed_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    completed_at = db.Column(db.DateTime(timezone=True), nullable=True)

    user = db.relationship("User", backref="manual_recovery_requests")


class AdminActionRequest(db.Model):
    __tablename__ = "admin_action_requests"

    id = db.Column(db.Integer, primary_key=True)
    operation_type = db.Column(db.String(80), nullable=False, index=True)
    target_type = db.Column(db.String(80), nullable=False, index=True)
    target_id = db.Column(db.String(64), nullable=False, index=True)
    operation_payload = db.Column(db.JSON, nullable=False, default=dict)
    requester_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=False, index=True)
    requester_role = db.Column(db.String(32), nullable=False)
    approver_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=True, index=True)
    status = db.Column(db.String(32), nullable=False, default="pending", index=True)
    reason_present = db.Column(db.Boolean, nullable=False, default=False)
    reason_length = db.Column(db.Integer, nullable=False, default=0)
    metadata_hmac = db.Column(db.String(64), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    decided_at = db.Column(db.DateTime(timezone=True), nullable=True)
    executed_at = db.Column(db.DateTime(timezone=True), nullable=True)

    requester = db.relationship(
        "User",
        foreign_keys=[requester_id],
        backref="requested_admin_actions",
    )
    approver = db.relationship(
        "User",
        foreign_keys=[approver_id],
        backref="approved_admin_actions",
    )

    __table_args__ = (
        db.CheckConstraint(
            (
                "operation_type IN ("
                "'staff_deactivate', 'staff_reactivate', 'staff_reset_activation', "
                "'manual_recovery_approve', 'manual_recovery_deny', 'manual_recovery_complete', "
                "'customer_security_unlock'"
                ")"
            ),
            name="ck_admin_action_requests_operation_type",
        ),
        db.CheckConstraint(
            "target_type IN ('staff_user', 'manual_recovery_request', 'customer_user')",
            name="ck_admin_action_requests_target_type",
        ),
        db.CheckConstraint(
            "requester_role IN ('root_admin')",
            name="ck_admin_action_requests_requester_role",
        ),
        db.CheckConstraint(
            "status IN ('pending', 'rejected', 'cancelled', 'expired', 'executed', 'execution_failed')",
            name="ck_admin_action_requests_status",
        ),
        Index("ix_admin_action_requests_status_expires_at", "status", "expires_at"),
    )


class ServerSideSession(db.Model):
    __tablename__ = "server_side_sessions"

    id = db.Column(db.Integer, primary_key=True)
    component = db.Column(db.String(32), nullable=False)
    session_lookup_hash = db.Column(db.String(64), nullable=False)
    session_ref = db.Column(db.String(32), nullable=True, index=True)
    payload = db.Column(db.LargeBinary, nullable=True)
    payload_format = db.Column(db.String(32), nullable=False, default="session-hmac-v2")
    user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=True, index=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_activity_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)
    ended_at = db.Column(db.DateTime(timezone=True), nullable=True)
    ended_reason = db.Column(db.String(32), nullable=True)
    ip_address = db.Column(db.String(64), nullable=False, default="")
    user_agent = db.Column(db.String(256), nullable=False, default="")
    risk_fingerprint = db.Column(db.String(64), nullable=False, default="")

    user = db.relationship("User", backref="server_side_sessions")

    __table_args__ = (
        db.UniqueConstraint(
            "component",
            "session_lookup_hash",
            name="uq_server_side_sessions_component_lookup_hash",
        ),
        Index(
            "ix_server_side_sessions_component_user_active",
            "component",
            "user_id",
            "revoked_at",
            "expires_at",
        ),
        Index("ix_server_side_sessions_last_activity_at", "last_activity_at"),
    )


class AuthAttemptCounter(db.Model):
    __tablename__ = "auth_attempt_counters"

    id = db.Column(db.Integer, primary_key=True)
    scope = db.Column(db.String(80), nullable=False)
    principal_hash = db.Column(db.String(64), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=True, index=True)
    ip_hash = db.Column(db.String(64), nullable=True, index=True)
    failure_count = db.Column(db.Integer, nullable=False, default=0)
    window_started_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    window_expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    last_failed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    user = db.relationship("User", backref="auth_attempt_counters")

    __table_args__ = (
        db.UniqueConstraint("scope", "principal_hash", name="uq_auth_attempt_counters_scope_principal"),
    )


class TotpReplayRecord(db.Model):
    __tablename__ = "totp_replay_records"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=False, index=True)
    scope = db.Column(db.String(80), nullable=False)
    time_step = db.Column(db.Integer, nullable=False)
    code_digest = db.Column(db.String(64), nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    user = db.relationship("User", backref="totp_replay_records")

    __table_args__ = (
        db.UniqueConstraint(
            "user_id",
            "scope",
            "time_step",
            "code_digest",
            name="uq_totp_replay_records_user_scope_step_digest",
        ),
    )


class RegistrationOtpChallenge(db.Model):
    __tablename__ = "registration_otp_challenges"

    id = db.Column(db.Integer, primary_key=True)
    session_binding_hash = db.Column(db.String(64), nullable=False)
    email_hash = db.Column(db.String(64), nullable=False)
    otp_hmac = db.Column(db.String(64), nullable=False)
    attempt_count = db.Column(db.Integer, nullable=False, default=0)
    resend_available_at = db.Column(db.DateTime(timezone=True), nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    used_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        db.UniqueConstraint(
            "session_binding_hash",
            "email_hash",
            name="uq_registration_otp_challenges_session_email",
        ),
    )


class StaffInvite(db.Model):
    __tablename__ = "staff_invites"

    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    workplace_email_normalized = db.Column(db.String(255), nullable=False, index=True)
    role = db.Column(db.String(32), nullable=False)
    status = db.Column(db.String(32), nullable=False, default="pending", index=True)
    delivery_status = db.Column(
        db.String(32),
        nullable=False,
        default="unconfirmed",
        server_default="unconfirmed",
    )
    created_by_user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=False, index=True)
    setup_user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=True, index=True)
    used_by_user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=True, index=True)
    revoked_by_user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=True, index=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    used_at = db.Column(db.DateTime(timezone=True), nullable=True)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)
    last_attempt_at = db.Column(db.DateTime(timezone=True), nullable=True)
    acceptance_session_hash = db.Column(db.String(64), nullable=True)
    acceptance_started_at = db.Column(db.DateTime(timezone=True), nullable=True)
    acceptance_start_count = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    acceptance_locked_at = db.Column(db.DateTime(timezone=True), nullable=True)
    workplace_verification_code_hmac = db.Column(db.String(64), nullable=True)
    workplace_verification_sent_at = db.Column(db.DateTime(timezone=True), nullable=True)
    workplace_verification_expires_at = db.Column(db.DateTime(timezone=True), nullable=True)
    workplace_verified_at = db.Column(db.DateTime(timezone=True), nullable=True)
    acceptance_verify_count = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    acceptance_verify_locked_at = db.Column(db.DateTime(timezone=True), nullable=True)

    created_by = db.relationship("User", foreign_keys=[created_by_user_id], backref="created_staff_invites")
    setup_user = db.relationship("User", foreign_keys=[setup_user_id], backref="pending_staff_invites")
    used_by = db.relationship("User", foreign_keys=[used_by_user_id], backref="accepted_staff_invites")
    revoked_by = db.relationship("User", foreign_keys=[revoked_by_user_id], backref="revoked_staff_invites")

    __table_args__ = (
        db.UniqueConstraint("token_hash"),
        db.CheckConstraint("role IN ('staff', 'admin')", name="ck_staff_invites_role"),
        db.CheckConstraint(
            "status IN ('pending', 'totp_pending', 'accepted', 'revoked', 'expired')",
            name="ck_staff_invites_status",
        ),
        db.CheckConstraint(
            "delivery_status IN ('unconfirmed', 'queued', 'failed')",
            name="ck_staff_invites_delivery_status",
        ),
    )


class PersonIdentityLink(db.Model):
    __tablename__ = "person_identity_links"

    id = db.Column(db.Integer, primary_key=True)
    staff_user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=False, index=True)
    customer_user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=False, index=True)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=True, index=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    verified_at = db.Column(db.DateTime(timezone=True), nullable=True)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    notes = db.Column(db.String(512), nullable=False, default="")

    staff_user = db.relationship("User", foreign_keys=[staff_user_id], backref="linked_customer_identities")
    customer_user = db.relationship("User", foreign_keys=[customer_user_id], backref="linked_staff_identities")
    created_by = db.relationship("User", foreign_keys=[created_by_user_id])

    __table_args__ = (
        db.UniqueConstraint(
            "staff_user_id",
            "customer_user_id",
            name="uq_person_identity_links_staff_customer",
        ),
    )


class PasswordResetTransaction(db.Model):
    __tablename__ = "password_reset_transactions"

    id = db.Column(db.Integer, primary_key=True)
    transaction_lookup_hash = db.Column(db.String(64), nullable=False, unique=True)
    token_id = db.Column(db.Integer, db.ForeignKey("password_reset_tokens.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=False, index=True)
    purpose = db.Column(db.String(40), nullable=False, default="password_reset")
    mfa_required = db.Column(db.String(40), nullable=False)
    available_mfa_methods_json = db.Column(db.JSON, nullable=False, default=list)
    preferred_mfa_method = db.Column(db.String(40), nullable=True)
    default_mfa_method = db.Column(db.String(40), nullable=True)
    mfa_verified = db.Column(db.Boolean, nullable=False, default=False)
    recovery_code_verified = db.Column(db.Boolean, nullable=False, default=False)
    no_mfa_user = db.Column(db.Boolean, nullable=False, default=False)
    failure_count = db.Column(db.Integer, nullable=False, default=0)
    last_failure_reason = db.Column(db.String(80), nullable=True)
    mfa_verified_at = db.Column(db.Integer, nullable=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    used_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    token = db.relationship("PasswordResetToken", backref="reset_transactions")
    user = db.relationship("User", backref="password_reset_transactions")

    __table_args__ = (
        Index("ix_password_reset_transactions_user_expires_at", "user_id", "expires_at"),
    )


class SecurityAlertDedupe(db.Model):
    __tablename__ = "security_alert_dedupe"

    id = db.Column(db.Integer, primary_key=True)
    dedupe_key_hash = db.Column(db.String(64), nullable=False, unique=True)
    event_type = db.Column(db.String(80), nullable=False)
    first_seen_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_seen_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    count = db.Column(db.Integer, nullable=False, default=1)


class SecurityCircuitBreaker(db.Model):
    __tablename__ = "security_circuit_breakers"

    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(80), nullable=False, unique=True)
    state = db.Column(db.String(16), nullable=False, default="closed")
    failure_count = db.Column(db.Integer, nullable=False, default=0)
    opened_until = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    last_failure_at = db.Column(db.DateTime(timezone=True), nullable=True)
    last_success_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class SecurityAuditEvent(db.Model):
    __tablename__ = "security_audit_events"

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(80), nullable=False, index=True)
    outcome = db.Column(db.String(24), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=True, index=True)
    ip_address = db.Column(db.String(64), nullable=False, default="")
    user_agent = db.Column(db.String(256), nullable=False, default="")
    correlation_id = db.Column(db.String(36), nullable=False, index=True)
    session_ref = db.Column(db.String(32), nullable=True)
    event_metadata = db.Column(db.JSON, nullable=False, default=dict)
    previous_event_hash = db.Column(db.String(64), nullable=True)
    event_hash = db.Column(db.String(64), nullable=True, index=True)
    hash_algorithm = db.Column(db.String(32), nullable=False, default="hmac-sha256-v1")
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    user = db.relationship("User", backref="security_audit_events")


class Payee(db.Model):
    __tablename__ = "payees"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=False, index=True)
    nickname = db.Column(db.String(64), nullable=False)
    account_number = db.Column(db.String(12), nullable=False)
    recipient_name = db.Column(db.String(128), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    user = db.relationship(
        "User",
        backref=db.backref("payees", cascade=_CASCADE_DELETE_ORPHAN, lazy="selectin"),
    )

    __table_args__ = (
        db.UniqueConstraint("user_id", "account_number", name="uq_payees_user_account"),
        db.CheckConstraint(
            (
                "length(account_number) = 12 AND "
                + " AND ".join(
                    f"substr(account_number, {position}, 1) BETWEEN '0' AND '9'"
                    for position in range(1, 13)
                )
            ),
            name="ck_payees_account_number_format",
        ),
    )

    def __repr__(self) -> str:
        return f"<Payee id={self.id!r} user_id={self.user_id!r} nickname={self.nickname!r}>"


class Transaction(db.Model):
    __tablename__ = "transactions"

    id = db.Column(db.Integer, primary_key=True)
    transaction_ref = db.Column(db.String(36), nullable=False)
    transaction_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    transaction_integrity_key_id = db.Column(db.String(32), nullable=False)
    transaction_integrity_algorithm = db.Column(db.String(32), nullable=False)
    transaction_integrity_version = db.Column(db.Integer, nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=False, index=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=False, index=True)
    payee_id = db.Column(db.Integer, db.ForeignKey("payees.id", ondelete="SET NULL"), nullable=True, index=True)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    reference = db.Column(db.String(128), nullable=False, default="")
    status = db.Column(db.String(32), nullable=False, default="completed")
    transaction_type = db.Column(
        db.String(32),
        nullable=False,
        default="local_transfer",
        server_default="local_transfer",
    )
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    sender = db.relationship(
        "User",
        foreign_keys=[sender_id],
        backref=db.backref("sent_transactions", lazy="selectin"),
    )
    recipient = db.relationship(
        "User",
        foreign_keys=[recipient_id],
        backref=db.backref("received_transactions", lazy="selectin"),
    )
    payee = db.relationship("Payee", backref="transactions")

    __table_args__ = (
        db.UniqueConstraint("transaction_ref", name="uq_transactions_ref"),
        Index("ix_transactions_transaction_ref", "transaction_ref"),
        db.CheckConstraint(
            "status IN ('completed', 'failed')",
            name="ck_transactions_status",
        ),
        db.CheckConstraint("amount > 0", name="ck_transactions_amount_positive"),
        db.CheckConstraint(
            "transaction_type IN ('local_transfer', 'payup')",
            name="ck_transactions_transaction_type",
        ),
        db.CheckConstraint(
            (
                "transaction_integrity_key_id IS NOT NULL "
                "AND transaction_integrity_algorithm = 'hmac-sha256' "
                "AND transaction_integrity_version = 1"
            ),
            name="ck_transactions_integrity_metadata",
        ),
    )

    def __repr__(self) -> str:
        return f"<Transaction id={self.id!r} ref={self.transaction_ref!r} amount={self.amount!r}>"


class RegistrationCredit(db.Model):
    __tablename__ = "registration_credits"

    id = db.Column(db.Integer, primary_key=True)
    credit_ref = db.Column(db.String(36), nullable=False, unique=True, index=True)
    credit_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    credit_integrity_key_id = db.Column(db.String(32), nullable=False)
    credit_integrity_algorithm = db.Column(db.String(32), nullable=False)
    credit_integrity_version = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=False, index=True)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    status = db.Column(db.String(32), nullable=False, default="completed", server_default="completed")
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    user = db.relationship("User", backref=db.backref("registration_credits", lazy="selectin"))

    __table_args__ = (
        db.UniqueConstraint("user_id", name="uq_registration_credits_user_id"),
        db.CheckConstraint("amount = 100.00", name="ck_registration_credits_amount_fixed"),
        db.CheckConstraint("status IN ('completed')", name="ck_registration_credits_status"),
        db.CheckConstraint(
            (
                "credit_integrity_key_id IS NOT NULL "
                "AND credit_integrity_algorithm = 'hmac-sha256' "
                "AND credit_integrity_version = 1"
            ),
            name="ck_registration_credits_integrity_metadata",
        ),
    )

    def __repr__(self) -> str:
        return f"<RegistrationCredit id={self.id!r} user_id={self.user_id!r} amount={self.amount!r}>"


class TopUpApprovalRequest(db.Model):
    __tablename__ = "topup_approval_requests"

    id = db.Column(db.Integer, primary_key=True)
    selector = db.Column(db.String(64), nullable=False, unique=True, index=True)
    verifier_hmac = db.Column(db.String(64), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=False, index=True)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    status = db.Column(db.String(32), nullable=False, default="pending", index=True)
    failure_count = db.Column(db.Integer, nullable=False, default=0)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    approved_at = db.Column(db.DateTime(timezone=True), nullable=True)
    credit_ref = db.Column(db.String(36), nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    user = db.relationship("User", backref=db.backref("topup_approval_requests", lazy="selectin"))

    __table_args__ = (
        db.CheckConstraint(
            "status IN ('pending', 'completed', 'expired', 'failed')",
            name="ck_topup_approval_requests_status",
        ),
        db.CheckConstraint(
            f"amount >= {MIN_TRANSACTION_AMOUNT} AND amount <= {MAX_TRANSACTION_AMOUNT}",
            name="ck_topup_approval_requests_amount_bounds",
        ),
    )

    def __repr__(self) -> str:
        return f"<TopUpApprovalRequest id={self.id!r} user_id={self.user_id!r} status={self.status!r}>"


class TopUpCredit(db.Model):
    __tablename__ = "topup_credits"

    id = db.Column(db.Integer, primary_key=True)
    credit_ref = db.Column(db.String(36), nullable=False, unique=True, index=True)
    credit_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    credit_integrity_key_id = db.Column(db.String(32), nullable=False)
    credit_integrity_algorithm = db.Column(db.String(32), nullable=False)
    credit_integrity_version = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=False, index=True)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    status = db.Column(db.String(32), nullable=False, default="completed", server_default="completed")
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    user = db.relationship("User", backref=db.backref("topup_credits", lazy="selectin"))

    __table_args__ = (
        db.CheckConstraint(
            f"amount >= {MIN_TRANSACTION_AMOUNT} AND amount <= {MAX_TRANSACTION_AMOUNT}",
            name="ck_topup_credits_amount_bounds",
        ),
        db.CheckConstraint("status IN ('completed')", name="ck_topup_credits_status"),
        db.CheckConstraint(
            (
                "credit_integrity_key_id IS NOT NULL "
                "AND credit_integrity_algorithm = 'hmac-sha256' "
                "AND credit_integrity_version = 1"
            ),
            name="ck_topup_credits_integrity_metadata",
        ),
    )

    def __repr__(self) -> str:
        return f"<TopUpCredit id={self.id!r} user_id={self.user_id!r} amount={self.amount!r}>"


class PublicTransactionIdempotency(db.Model):
    __tablename__ = "public_transaction_idempotency"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey(_USER_ID_FOREIGN_KEY, ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    hmac_key_id = db.Column(db.String(32), nullable=False)
    key_fingerprint = db.Column(db.String(64), nullable=False)
    key_verifier = db.Column(db.String(64), nullable=False)
    payload_verifier = db.Column(db.String(64), nullable=False)
    status = db.Column(
        db.String(24),
        nullable=False,
        default="reserved",
        server_default="reserved",
    )
    result_reference = db.Column(db.String(64), nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)

    user = db.relationship(
        "User",
        backref=db.backref(
            "public_transaction_idempotency_records",
            cascade=_CASCADE_DELETE_ORPHAN,
            lazy="selectin",
        ),
    )

    __table_args__ = (
        db.UniqueConstraint(
            "user_id",
            "key_fingerprint",
            name="uq_public_transaction_idempotency_user_key",
        ),
        db.CheckConstraint(
            "status IN ('reserved', 'completed', 'failed')",
            name="ck_public_transaction_idempotency_status",
        ),
    )


DISPUTE_ISSUE_TYPES = (
    "unauthorized_transaction",
    "duplicate_charge",
    "incorrect_amount",
    "recipient_service_issue",
    "other",
)
DISPUTE_OPEN_STATUSES = ("open", "under_review")


class TransactionDispute(db.Model):
    __tablename__ = "transaction_disputes"

    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.Integer, db.ForeignKey("transactions.id"), nullable=False, index=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=False, index=True)
    issue_type = db.Column(db.String(32), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(32), nullable=False, default="open", index=True)
    resolver_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=True, index=True)
    resolution_note = db.Column(db.Text, nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    decided_at = db.Column(db.DateTime(timezone=True), nullable=True)

    transaction = db.relationship("Transaction", backref=db.backref("disputes", lazy="selectin"))
    reporter = db.relationship(
        "User",
        foreign_keys=[reporter_id],
        backref="filed_transaction_disputes",
    )
    resolver = db.relationship(
        "User",
        foreign_keys=[resolver_id],
        backref="resolved_transaction_disputes",
    )

    __table_args__ = (
        db.CheckConstraint(
            "issue_type IN ('unauthorized_transaction', 'duplicate_charge', 'incorrect_amount', "
            "'recipient_service_issue', 'other')",
            name="ck_transaction_disputes_issue_type",
        ),
        db.CheckConstraint(
            "status IN ('open', 'under_review', 'resolved', 'rejected')",
            name="ck_transaction_disputes_status",
        ),
        Index(
            "ux_transaction_disputes_one_open_per_txn",
            "transaction_id",
            unique=True,
            postgresql_where=status.in_(DISPUTE_OPEN_STATUSES),
            sqlite_where=status.in_(DISPUTE_OPEN_STATUSES),
        ),
    )

    def __repr__(self) -> str:
        return f"<TransactionDispute id={self.id!r} transaction_id={self.transaction_id!r} status={self.status!r}>"


class _PendingTransferColumnsMixin:
    """Columns shared by PendingTransfer and PayupPendingTransfer."""

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), nullable=False, unique=True, index=True)
    amount = db.Column(db.Numeric(12, 5), nullable=False)
    reference = db.Column(db.String(128), nullable=False, default="", server_default="")
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    consumed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    consumed_transaction_ref = db.Column(db.String(36), nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class PendingTransfer(_PendingTransferColumnsMixin, db.Model):
    __tablename__ = "pending_transfers"

    user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=False, index=True)
    payee_id = db.Column(db.Integer, db.ForeignKey("payees.id"), nullable=False, index=True)

    user = db.relationship(
        "User",
        backref=db.backref("pending_transfers", lazy="selectin"),
    )
    payee = db.relationship("Payee", backref=db.backref("pending_transfers", lazy="selectin"))

    __table_args__ = (
        db.UniqueConstraint("token", name="uq_pending_transfers_token"),
    )

    def __repr__(self) -> str:
        return f"<PendingTransfer id={self.id!r} user_id={self.user_id!r} consumed={self.consumed_at is not None!r}>"


class PayupPendingTransfer(_PendingTransferColumnsMixin, db.Model):
    __tablename__ = "payup_pending_transfers"

    user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=False, index=True)
    recipient_user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=False, index=True)

    user = db.relationship(
        "User",
        foreign_keys=[user_id],
        backref=db.backref("payup_pending_transfers", lazy="selectin"),
    )
    recipient_user = db.relationship("User", foreign_keys=[recipient_user_id])

    __table_args__ = (
        db.UniqueConstraint("token", name="uq_payup_pending_transfers_token"),
    )

    def __repr__(self) -> str:
        return f"<PayupPendingTransfer id={self.id!r} user_id={self.user_id!r} consumed={self.consumed_at is not None!r}>"
