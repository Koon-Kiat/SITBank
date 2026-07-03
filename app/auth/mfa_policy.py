from __future__ import annotations

from flask import session

from app.models import User


PASSWORD_BOOTSTRAP_AUTH_CONTEXT = "password_bootstrap"


def has_enrolled_mfa_method(user: User) -> bool:
    return bool(user.mfa_enabled)


def has_password_bootstrap_session(user: User) -> bool:
    return (
        session.get("user_id") == user.id
        and session.get("auth_context") == PASSWORD_BOOTSTRAP_AUTH_CONTEXT
    )
