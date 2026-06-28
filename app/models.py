from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

from sqlalchemy import Index, func

from .extensions import db

_USER_ID_FOREIGN_KEY = "users.id"


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    account_type = db.Column(db.String(32), nullable=False, default="customer", index=True)
    account_status = db.Column(db.String(32), nullable=False, default="active", index=True)
    full_name = db.Column(db.String(128), nullable=False)
    phone_number = db.Column(db.String(8), nullable=True, unique=True)
    account_number = db.Column(db.String(9), nullable=True, unique=True)
    staff_personal_email = db.Column(db.String(255), nullable=True)
    workplace_email_verified_at = db.Column(db.DateTime(timezone=True), nullable=True)

    mfa_secret_ciphertext = db.Column(db.LargeBinary, nullable=True)
    mfa_secret_nonce = db.Column(db.LargeBinary(12), nullable=True)
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    mfa_step_up_preference = db.Column(db.String(32), nullable=False, default="totp")

    balance = db.Column(
        db.Numeric(12, 2),
        nullable=False,
        default=Decimal("0.00"),
        server_default="0.00",
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
        db.CheckConstraint(
            "account_type IN ('customer', 'staff', 'admin', 'root_admin')",
            name="ck_users_account_type",
        ),
        db.CheckConstraint(
            "account_status IN ('active', 'setup_pending', 'revoked', 'locked')",
            name="ck_users_account_status",
        ),
        db.CheckConstraint("balance >= 0", name="ck_users_balance_non_negative"),
    )

    def __repr__(self) -> str:
        return f"<User id={self.id!r} username={self.username!r}>"


class WebAuthnCredential(db.Model):
    __tablename__ = "webauthn_credentials"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=False, index=True)
    credential_id = db.Column(db.LargeBinary, nullable=False, unique=True)
    credential_public_key = db.Column(db.LargeBinary, nullable=False)
    sign_count = db.Column(db.Integer, nullable=False, default=0)
    label = db.Column(db.String(80), nullable=False)
    aaguid = db.Column(db.String(36), nullable=False, index=True)
    attestation_format = db.Column(db.String(32), nullable=False)
    transports = db.Column(db.JSON, nullable=False, default=list)
    credential_device_type = db.Column(db.String(32), nullable=False)
    credential_backed_up = db.Column(db.Boolean, nullable=False, default=False)
    credential_kind = db.Column(db.String(32), nullable=False, default="passkey")
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_used_at = db.Column(db.DateTime(timezone=True), nullable=True)

    user = db.relationship(
        "User",
        backref=db.backref(
            "webauthn_credentials",
            cascade="all, delete-orphan",
            lazy="selectin",
        ),
    )

    __table_args__ = (
        Index("ix_webauthn_credentials_user_label_lower", user_id, func.lower(label), unique=True),
    )

    def __repr__(self) -> str:
        return f"<WebAuthnCredential id={self.id!r} user_id={self.user_id!r} label={self.label!r}>"


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
    code_hmac = db.Column(db.String(64), nullable=False, unique=True)
    purpose = db.Column(db.String(40), nullable=False, default="totp_recovery")
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    used_at = db.Column(db.DateTime(timezone=True), nullable=True)

    user = db.relationship("User", backref="recovery_codes")


class ManualRecoveryRequest(db.Model):
    __tablename__ = "manual_recovery_requests"

    id = db.Column(db.Integer, primary_key=True)
    identifier_ref = db.Column(db.String(64), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=True, index=True)
    status = db.Column(db.String(32), nullable=False, default="pending")
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
    personal_email_normalized = db.Column(db.String(255), nullable=False, index=True)
    workplace_email_normalized = db.Column(db.String(255), nullable=False, index=True)
    role = db.Column(db.String(32), nullable=False)
    status = db.Column(db.String(32), nullable=False, default="pending", index=True)
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
    workplace_verification_code_hmac = db.Column(db.String(64), nullable=True)
    workplace_verification_sent_at = db.Column(db.DateTime(timezone=True), nullable=True)
    workplace_verification_expires_at = db.Column(db.DateTime(timezone=True), nullable=True)
    workplace_verified_at = db.Column(db.DateTime(timezone=True), nullable=True)

    created_by = db.relationship("User", foreign_keys=[created_by_user_id], backref="created_staff_invites")
    setup_user = db.relationship("User", foreign_keys=[setup_user_id], backref="pending_staff_invites")
    used_by = db.relationship("User", foreign_keys=[used_by_user_id], backref="accepted_staff_invites")
    revoked_by = db.relationship("User", foreign_keys=[revoked_by_user_id], backref="revoked_staff_invites")

    __table_args__ = (
        db.CheckConstraint("role IN ('staff', 'admin')", name="ck_staff_invites_role"),
        db.CheckConstraint(
            "status IN ('pending', 'totp_pending', 'accepted', 'revoked', 'expired')",
            name="ck_staff_invites_status",
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
    account_number = db.Column(db.String(9), nullable=False)
    recipient_name = db.Column(db.String(128), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    user = db.relationship(
        "User",
        backref=db.backref("payees", cascade="all, delete-orphan", lazy="selectin"),
    )

    __table_args__ = (
        db.UniqueConstraint("user_id", "account_number", name="uq_payees_user_account"),
    )

    def __repr__(self) -> str:
        return f"<Payee id={self.id!r} user_id={self.user_id!r} nickname={self.nickname!r}>"


class Transaction(db.Model):
    __tablename__ = "transactions"

    id = db.Column(db.Integer, primary_key=True)
    transaction_ref = db.Column(db.String(36), nullable=False, unique=True, index=True)
    transaction_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    sender_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=False, index=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=False, index=True)
    payee_id = db.Column(db.Integer, db.ForeignKey("payees.id"), nullable=True, index=True)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    reference = db.Column(db.String(128), nullable=False, default="")
    status = db.Column(db.String(32), nullable=False, default="completed")
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
        db.CheckConstraint(
            "status IN ('completed', 'failed')",
            name="ck_transactions_status",
        ),
        db.CheckConstraint("amount > 0", name="ck_transactions_amount_positive"),
    )

    def __repr__(self) -> str:
        return f"<Transaction id={self.id!r} ref={self.transaction_ref!r} amount={self.amount!r}>"


class PendingTransfer(db.Model):
    __tablename__ = "pending_transfers"

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), nullable=False, unique=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey(_USER_ID_FOREIGN_KEY), nullable=False, index=True)
    payee_id = db.Column(db.Integer, db.ForeignKey("payees.id"), nullable=False, index=True)
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

    user = db.relationship(
        "User",
        backref=db.backref("pending_transfers", lazy="selectin"),
    )
    payee = db.relationship("Payee", backref=db.backref("pending_transfers", lazy="selectin"))

    def __repr__(self) -> str:
        return f"<PendingTransfer id={self.id!r} user_id={self.user_id!r} consumed={self.consumed_at is not None!r}>"
