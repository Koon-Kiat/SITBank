from __future__ import annotations

from functools import wraps
from time import time

from flask import current_app, g, jsonify, session

from app.admin.services import is_customer_user


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id") or getattr(g, "current_user", None) is None:
            return jsonify({"error": "Authentication required"}), 401
        if current_app.config.get("APP_MODE") == "customer" and not is_customer_user(g.current_user):
            return jsonify({"error": "Forbidden"}), 403
        return view(*args, **kwargs)

    return wrapped


def mfa_verified_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("mfa_verified_at"):
            return jsonify({"error": "MFA verification required"}), 403
        return view(*args, **kwargs)

    return wrapped


def fresh_mfa_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        verified_at = int(session.get("fresh_mfa_verified_at") or 0)
        if time() - verified_at > current_app.config["FRESH_MFA_SECONDS"]:
            return jsonify({"error": "Fresh MFA verification required"}), 403
        return view(*args, **kwargs)

    return wrapped


def not_frozen_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = getattr(g, "current_user", None)
        if user is not None and (user.is_frozen or user.security_locked_at is not None):
            return jsonify({"error": "Account is frozen"}), 403
        return view(*args, **kwargs)

    return wrapped
