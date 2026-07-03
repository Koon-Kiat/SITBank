from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from flask import Flask, g, jsonify, render_template, request
from flask_wtf.csrf import CSRFError
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config, apply_runtime_mode_config

from .admin.routes import admin_bp
from .auth.routes import auth_bp
from .auth.services import warm_dummy_password_hash
from .banking.routes import banking_bp
from .extensions import csrf, db, limiter, migrate, talisman
from .main.routes import main_bp
from .models import User
from .ops.commands import register_ops_commands
from .security.audit import register_correlation_id
from .security.cloudflare_access import register_cloudflare_access_guard
from .security.sessions import install_database_sessions, register_session_hooks
from .security.http_errors import (
    CSRF_ERROR_MESSAGE,
    RATE_LIMIT_MESSAGE,
    safe_error_response,
)
from .security.turnstile import register_turnstile_template_helpers
from .web.routes import web_bp


def create_app(config_object: type[Config] = Config, *, app_mode: str = "customer") -> Flask:
    app = Flask(__name__)
    app.logger.disabled = False
    app.config.from_object(config_object)
    apply_runtime_mode_config(app.config, app_mode)
    trusted_proxy_count = app.config["TRUSTED_PROXY_COUNT"]
    if trusted_proxy_count:
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=trusted_proxy_count,
            x_proto=trusted_proxy_count,
            x_host=trusted_proxy_count,
            x_port=trusted_proxy_count,
        )

    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    limiter.init_app(app)
    talisman.init_app(
        app,
        force_https=app.config["TALISMAN_FORCE_HTTPS"],
        content_security_policy=app.config["TALISMAN_CONTENT_SECURITY_POLICY"],
        session_cookie_secure=app.config["SESSION_COOKIE_SECURE"],
        session_cookie_http_only=app.config["SESSION_COOKIE_HTTPONLY"],
        session_cookie_samesite=app.config["SESSION_COOKIE_SAMESITE"],
    )
    install_database_sessions(app)

    register_correlation_id(app)
    register_cloudflare_access_guard(app)
    register_session_hooks(app)
    register_current_user_loader(app)
    register_forced_password_change_guard(app)
    register_error_handlers(app)
    register_no_store_headers(app)
    register_datetime_template_helpers(app)
    register_turnstile_template_helpers(app)
    register_ops_commands(app)

    with app.app_context():
        warm_dummy_password_hash()

    if app.config["APP_MODE"] == "customer":
        app.register_blueprint(auth_bp)
        app.register_blueprint(banking_bp)
        app.register_blueprint(web_bp)
        app.register_blueprint(main_bp)
    else:
        app.register_blueprint(admin_bp)

    return app


def create_customer_app(config_object: type[Config] = Config) -> Flask:
    return create_app(config_object, app_mode="customer")


def create_admin_app(config_object: type[Config] = Config) -> Flask:
    return create_app(config_object, app_mode="admin")


def register_current_user_loader(app: Flask) -> None:
    @app.before_request
    def load_current_user() -> None:
        from flask import g, session

        g.current_user = None
        g.webauthn_credential_count = 0
        g.legacy_passkey_credential_count = 0
        g.webauthn_required_count = 0
        g.passkey_ready = False
        g.mfa_ready = False
        g.high_risk_ready = False
        user_id = session.get("user_id")
        if user_id is not None:
            g.current_user = db.session.get(User, user_id)
            if g.current_user is not None:
                from app.auth.mfa_policy import has_enrolled_mfa_method
                from app.auth.webauthn_services import webauthn_credential_count

                g.webauthn_credential_count = webauthn_credential_count(g.current_user)
                g.legacy_passkey_credential_count = g.webauthn_credential_count
                g.mfa_ready = has_enrolled_mfa_method(g.current_user)
                g.high_risk_ready = g.mfa_ready


def register_forced_password_change_guard(app: Flask) -> None:
    @app.before_request
    def enforce_forced_password_change():
        user = getattr(g, "current_user", None)
        if user is None or not getattr(user, "force_password_change", False):
            return None
        allowed_endpoints = {
            "auth.csrf_token",
            "auth.logout",
            "auth.session_extend",
            "auth.password_change",
            "auth.password_reset_request",
            "auth.password_reset_exchange",
            "auth.password_reset_transaction",
            "auth.password_reset_mfa_method",
            "auth.password_reset_totp",
            "auth.password_reset_recovery_code",
            "auth.password_reset_complete",
            "auth.manual_recovery_request",
            "web.logout",
            "web.password_change",
            "web.password_change_submit",
            "web.forgot_password",
            "web.forgot_password_submit",
            "web.reset_password_exchange",
            "web.reset_password_continue",
            "web.reset_password_continue_submit",
            "web.account_recovery",
            "web.account_recovery_submit",
            "web.mfa_setup",
            "web.mfa_setup_submit",
            "admin.logout",
        }
        if request.endpoint in allowed_endpoints:
            return None
        from .security.audit import audit_event

        audit_event(
            "forced_password_change",
            "required",
            user=user,
            metadata={
                "reason": str(getattr(user, "force_password_change_reason", "") or "security_event"),
                "endpoint": request.endpoint or "",
            },
        )
        if app.config.get("APP_MODE") == "admin" or request.path.startswith("/auth/"):
            return jsonify(
                {
                    "error": "Password change required",
                    "code": "password_change_required",
                }
            ), 403
        return render_template("error.html", message="Password change required", status_code=403), 403


def register_error_handlers(app: Flask) -> None:
    def respond(message: str, status_code: int):
        return safe_error_response(message, status_code)

    @app.errorhandler(CSRFError)
    def csrf_error(error):
        return respond(CSRF_ERROR_MESSAGE, 400)

    @app.errorhandler(400)
    def bad_request(error):
        return respond("Bad request", 400)

    @app.errorhandler(401)
    def unauthorized(error):
        return respond("Authentication required", 401)

    @app.errorhandler(403)
    def forbidden(error):
        return respond("Forbidden", 403)

    @app.errorhandler(404)
    def not_found(error):
        return respond("Not found", 404)

    @app.errorhandler(429)
    def rate_limited(error):
        from .security.audit import audit_event

        audit_event("rate_limit", "blocked", metadata={"path": request.path})
        return respond(RATE_LIMIT_MESSAGE, 429)

    @app.errorhandler(500)
    def internal_error(error):
        original_error = getattr(error, "original_exception", None) or error
        app.logger.error(
            json.dumps(
                {
                    "message": "system_error",
                    "correlation_id": getattr(g, "correlation_id", ""),
                    "path": request.path,
                    "method": request.method,
                    "exception_type": type(original_error).__name__,
                    "logged_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return respond("Server error. Please try again later.", 500)


def register_datetime_template_helpers(app: Flask) -> None:
    singapore_tz = timezone(timedelta(hours=8))

    @app.template_filter("sgt")
    def to_singapore_time(value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(singapore_tz)


def register_no_store_headers(app: Flask) -> None:
    @app.after_request
    def no_store_authenticated_responses(response):
        from flask import session

        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")

        if (
            session.get("user_id")
            or session.get("pending_mfa_user_id")
            or request.path.startswith(
                (
                    "/forgot-password",
                    "/reset-password",
                    "/account-recovery",
                    "/auth/password-reset",
                    "/auth/account-recovery",
                )
            )
        ):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response
