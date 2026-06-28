from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import pyotp
from flask import current_app
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.auth.services import AuthError
from app.models import User
from app.security.audit import audit_reference, audit_system_event
from app.security.crypto import encrypt_mfa_secret
from app.security.passwords import PasswordPolicyError, hash_password, validate_password_policy

from .services import (
    ACCOUNT_CUSTOMER,
    ACCOUNT_ROOT_ADMIN,
    STAFF_ACCOUNT_TYPES,
    STAFF_USERNAME_RE,
    normalize_workplace_email,
    validate_full_name,
)


class RootAdminBootstrapError(ValueError):
    """Raised when the root-admin bootstrap request is not allowed."""


@dataclass(frozen=True)
class RootAdminBootstrapResult:
    user_id: int
    workplace_email: str
    username: str
    created: bool
    reset_existing: bool
    manual_entry_secret: str
    otpauth_uri: str


def bootstrap_root_admin(
    *,
    workplace_email: str,
    username: str,
    full_name: str,
    password: str,
    reset_existing: bool = False,
) -> RootAdminBootstrapResult:
    """Create or explicitly reset one allowlisted root-admin identity."""

    _require_admin_runtime()
    normalized_email = _validate_workplace_email(workplace_email)
    normalized_username = _validate_username(username)
    normalized_full_name = _validate_full_name(full_name)
    _require_allowlisted_root_email(normalized_email)
    _validate_bootstrap_password(password)

    existing = _user_for_update(normalized_email)
    created = existing is None
    if existing is not None and existing.account_type == ACCOUNT_CUSTOMER:
        _audit_bootstrap("blocked", normalized_email, reason="customer_identity_exists")
        raise RootAdminBootstrapError(
            "Refusing to convert an existing customer account into a root admin"
        )
    if existing is not None and not reset_existing:
        _audit_bootstrap("blocked", normalized_email, user_id=existing.id, reason="reset_existing_required")
        raise RootAdminBootstrapError(
            "Root admin identity already exists; rerun with --reset-existing to rotate credentials"
        )

    _reject_username_conflict(normalized_username, existing.id if existing else None)
    password_hash = hash_password(password)

    user = existing or User(
        username=normalized_username,
        email=normalized_email,
        password_hash=password_hash,
        account_type=ACCOUNT_ROOT_ADMIN,
        account_status="active",
        full_name=normalized_full_name,
        phone_number=None,
        account_number=None,
        staff_personal_email=None,
    )
    if existing is None:
        db.session.add(user)
        db.session.flush()

    secret = pyotp.random_base32(length=32)
    user.username = normalized_username
    user.email = normalized_email
    user.full_name = normalized_full_name
    user.password_hash = password_hash
    user.account_type = ACCOUNT_ROOT_ADMIN
    user.account_status = "active"
    user.account_number = None
    user.staff_personal_email = None
    user.workplace_email_verified_at = datetime.now(timezone.utc)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(secret, user.id)
    user.mfa_enabled = True
    user.mfa_step_up_preference = "totp"

    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        _audit_bootstrap("failure", normalized_email, reason="integrity_error")
        raise RootAdminBootstrapError("Root admin bootstrap failed integrity checks") from exc

    _audit_bootstrap(
        "success",
        normalized_email,
        user_id=user.id,
        created=created,
        reset_existing=bool(reset_existing and not created),
    )
    return RootAdminBootstrapResult(
        user_id=user.id,
        workplace_email=normalized_email,
        username=user.username,
        created=created,
        reset_existing=bool(reset_existing and not created),
        manual_entry_secret=secret,
        otpauth_uri=_totp_provisioning_uri(normalized_email, secret),
    )


def _require_admin_runtime() -> None:
    if current_app.config.get("APP_MODE") != "admin":
        raise RootAdminBootstrapError("Root admin bootstrap must run with the admin app")


def _require_allowlisted_root_email(email: str) -> None:
    root_emails = frozenset(str(item).casefold() for item in current_app.config["ROOT_ADMIN_EMAILS"])
    if email.casefold() not in root_emails:
        _audit_bootstrap("blocked", email, reason="email_not_allowlisted")
        raise RootAdminBootstrapError("Root admin email is not listed in ROOT_ADMIN_EMAILS")


def _validate_username(username: str) -> str:
    text = str(username or "").strip()
    if not STAFF_USERNAME_RE.fullmatch(text):
        raise RootAdminBootstrapError(
            "Username must be 3-64 characters and contain only letters, numbers, dots, underscores, or hyphens"
        )
    return text


def _validate_workplace_email(email: str) -> str:
    try:
        return normalize_workplace_email(email)
    except AuthError as exc:
        raise RootAdminBootstrapError(str(exc)) from exc


def _validate_full_name(full_name: str) -> str:
    try:
        return validate_full_name(full_name)
    except AuthError as exc:
        raise RootAdminBootstrapError(str(exc)) from exc


def _validate_bootstrap_password(password: str) -> None:
    try:
        validate_password_policy(password)
    except PasswordPolicyError as exc:
        raise RootAdminBootstrapError(str(exc)) from exc


def _user_for_update(email: str) -> User | None:
    statement = db.select(User).where(
        func.lower(User.email) == email.casefold(),
        User.account_type.in_(tuple(STAFF_ACCOUNT_TYPES | {ACCOUNT_CUSTOMER})),
    )
    if db.engine.dialect.name == "postgresql":
        statement = statement.with_for_update()
    return db.session.execute(statement).scalar_one_or_none()


def _reject_username_conflict(username: str, current_user_id: int | None) -> None:
    statement = db.select(User).where(func.lower(User.username) == username.casefold())
    if current_user_id is not None:
        statement = statement.where(User.id != current_user_id)
    if db.session.execute(statement).scalar_one_or_none() is not None:
        raise RootAdminBootstrapError("Username is already in use")


def _totp_provisioning_uri(email: str, secret: str) -> str:
    return pyotp.TOTP(secret, digits=6, interval=30).provisioning_uri(
        name=email,
        issuer_name=current_app.config["MFA_ISSUER_NAME"],
    )


def _audit_bootstrap(
    outcome: str,
    email: str,
    *,
    user_id: int | None = None,
    reason: str | None = None,
    created: bool | None = None,
    reset_existing: bool | None = None,
) -> None:
    metadata: dict[str, object] = {
        "root_admin_email_ref": audit_reference("root_admin_email", email),
    }
    if reason:
        metadata["reason"] = reason
    if created is not None:
        metadata["created"] = created
    if reset_existing is not None:
        metadata["reset_existing"] = reset_existing
    audit_system_event("root_admin_bootstrap", outcome, user_id=user_id, metadata=metadata)
