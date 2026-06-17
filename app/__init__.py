from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from flask import Flask, g, jsonify, render_template, request
from flask_wtf.csrf import CSRFError
from redis import Redis
from redis.backoff import NoBackoff
from redis.retry import Retry
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config

from .auth.routes import auth_bp
from .auth.services import warm_dummy_password_hash
from .banking.routes import banking_bp
from .extensions import csrf, db, limiter, migrate, talisman
from .main.routes import main_bp
from .models import User
from .ops.commands import register_ops_commands
from .security.audit import register_correlation_id
from .security.sessions import install_uuid_redis_sessions, register_session_hooks
from .web.routes import web_bp


def redis_connection_options(config: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "protocol": config["REDIS_PROTOCOL"],
        "legacy_responses": config["REDIS_LEGACY_RESPONSES"],
        "socket_connect_timeout": config["REDIS_SOCKET_CONNECT_TIMEOUT_SECONDS"],
        "socket_timeout": config["REDIS_SOCKET_TIMEOUT_SECONDS"],
        "socket_keepalive": True,
        "health_check_interval": config["REDIS_HEALTH_CHECK_INTERVAL_SECONDS"],
        "max_connections": config["REDIS_MAX_CONNECTIONS"],
        "retry_on_timeout": False,
        "retry": Retry(NoBackoff(), retries=0),
    }


def create_app(config_object: type[Config] = Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_object)
    trusted_proxy_count = app.config["TRUSTED_PROXY_COUNT"]
    if trusted_proxy_count:
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=trusted_proxy_count,
            x_proto=trusted_proxy_count,
            x_host=trusted_proxy_count,
            x_port=trusted_proxy_count,
        )

    redis_client = Redis.from_url(
        app.config["REDIS_URL"],
        decode_responses=True,
        client_name="sitbank-application",
        **redis_connection_options(app.config),
    )
    redis_session_client = Redis.from_url(
        app.config["REDIS_URL"],
        decode_responses=False,
        client_name="sitbank-session",
        **redis_connection_options(app.config),
    )
    app.extensions["redis"] = redis_client
    app.extensions["redis_session"] = redis_session_client

    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    if app.config["RATELIMIT_STORAGE_URI"].startswith(("redis://", "rediss://")):
        app.config["RATELIMIT_STORAGE_OPTIONS"] = {
            **redis_connection_options(app.config),
            "client_name": "sitbank-rate-limiter",
        }
    limiter.init_app(app)
    talisman.init_app(
        app,
        force_https=app.config["TALISMAN_FORCE_HTTPS"],
        content_security_policy=app.config["TALISMAN_CONTENT_SECURITY_POLICY"],
        session_cookie_secure=app.config["SESSION_COOKIE_SECURE"],
        session_cookie_http_only=app.config["SESSION_COOKIE_HTTPONLY"],
        session_cookie_samesite=app.config["SESSION_COOKIE_SAMESITE"],
    )
    install_uuid_redis_sessions(app, redis_session_client)

    register_correlation_id(app)
    register_session_hooks(app)
    register_current_user_loader(app)
    register_error_handlers(app)
    register_no_store_headers(app)
    register_ops_commands(app)

    with app.app_context():
        warm_dummy_password_hash()

    app.register_blueprint(auth_bp)
    app.register_blueprint(banking_bp)
    app.register_blueprint(web_bp)
    app.register_blueprint(main_bp)

    return app


def register_current_user_loader(app: Flask) -> None:
    @app.before_request
    def load_current_user() -> None:
        from flask import g, session

        g.current_user = None
        g.webauthn_credential_count = 0
        g.webauthn_required_count = app.config.get("WEBAUTHN_REQUIRED_CREDENTIALS", 2)
        g.high_risk_ready = False
        user_id = session.get("user_id")
        if user_id is not None:
            g.current_user = db.session.get(User, user_id)
            if g.current_user is not None:
                from app.auth.webauthn_services import webauthn_credential_count

                g.webauthn_credential_count = webauthn_credential_count(g.current_user)
                g.high_risk_ready = g.webauthn_credential_count >= g.webauthn_required_count


def register_error_handlers(app: Flask) -> None:
    def wants_json() -> bool:
        if request.path.startswith("/auth/"):
            return True
        best = request.accept_mimetypes.best_match(["application/json", "text/html"])
        return best == "application/json" and (
            request.accept_mimetypes["application/json"] >= request.accept_mimetypes["text/html"]
        )

    def respond(message: str, status_code: int):
        if wants_json():
            return jsonify({"error": message}), status_code
        return render_template("error.html", message=message, status_code=status_code), status_code

    @app.errorhandler(CSRFError)
    def csrf_error(error):
        return respond("Security token expired or invalid. Please try again.", 400)

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
        return respond("Too many attempts. Please try again later.", 429)

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


def register_no_store_headers(app: Flask) -> None:
    @app.after_request
    def no_store_authenticated_responses(response):
        from flask import session

        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")

        if session.get("user_id") or session.get("pending_mfa_user_id"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response
