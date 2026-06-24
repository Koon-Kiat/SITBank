from __future__ import annotations

from flask import session

from app.extensions import db
from app.models import User, WebAuthnCredential


PASSWORD_BOOTSTRAP_AUTH_CONTEXT = "password_bootstrap"


def enrolled_webauthn_credential_count(user: User) -> int:
    if user.id is None:
        return 0
    return int(
        db.session.execute(
            db.select(db.func.count(WebAuthnCredential.id)).where(
                WebAuthnCredential.user_id == user.id
            )
        ).scalar_one()
    )


def has_enrolled_mfa_method(user: User) -> bool:
    return bool(user.mfa_enabled or enrolled_webauthn_credential_count(user) > 0)


def has_password_bootstrap_session(user: User) -> bool:
    return (
        session.get("user_id") == user.id
        and session.get("auth_context") == PASSWORD_BOOTSTRAP_AUTH_CONTEXT
    )
