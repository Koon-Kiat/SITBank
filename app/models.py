from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Index, func

from .extensions import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(128), nullable=False)
    phone_number = db.Column(db.String(8), nullable=False, unique=True)
    account_number = db.Column(db.String(9), nullable=False, unique=True)

    mfa_secret_ciphertext = db.Column(db.LargeBinary, nullable=True)
    mfa_secret_nonce = db.Column(db.LargeBinary(12), nullable=True)
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    mfa_step_up_preference = db.Column(db.String(32), nullable=False, default="totp")

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
    )

    def __repr__(self) -> str:
        return f"<User id={self.id!r} username={self.username!r}>"


class RegistrationInvite(db.Model):
    __tablename__ = "registration_invites"

    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    intended_email_normalized = db.Column(db.String(255), nullable=False, index=True)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    used_at = db.Column(db.DateTime(timezone=True), nullable=True)
    used_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)
    revoked_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    last_attempt_at = db.Column(db.DateTime(timezone=True), nullable=True)

    created_by = db.relationship("User", foreign_keys=[created_by_user_id])
    used_by = db.relationship("User", foreign_keys=[used_by_user_id])
    revoked_by = db.relationship("User", foreign_keys=[revoked_by_user_id])

    def __repr__(self) -> str:
        return f"<RegistrationInvite id={self.id!r} email={self.intended_email_normalized!r}>"


class WebAuthnCredential(db.Model):
    __tablename__ = "webauthn_credentials"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
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
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
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
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
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
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
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


class SecurityAuditEvent(db.Model):
    __tablename__ = "security_audit_events"

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(80), nullable=False, index=True)
    outcome = db.Column(db.String(24), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
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
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
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
