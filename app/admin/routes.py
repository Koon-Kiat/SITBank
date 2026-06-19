from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request, session
from sqlalchemy import text

from app.extensions import csrf, db
from app.security.audit import audit_event


admin_bp = Blueprint("admin", __name__)


def _request_payload_keys() -> list[str]:
    payload = request.get_json(silent=True)
    if isinstance(payload, dict):
        return sorted(str(key)[:64] for key in payload)
    return sorted(str(key)[:64] for key in request.form.keys())


def _audit_admin_denial(event_type: str, outcome: str) -> None:
    audit_event(
        event_type,
        outcome,
        metadata={
            "app_mode": "admin",
            "path": request.path,
            "payload_keys": _request_payload_keys(),
            "password": (request.get_json(silent=True) or request.form or {}).get("password"),
            "token": (request.get_json(silent=True) or request.form or {}).get("token"),
            "phase": "phase_1a_fail_closed",
        },
    )


@admin_bp.get("/health/live")
def health_live():
    return jsonify({"status": "ok", "app_mode": "admin"})


@admin_bp.get("/health/ready")
def health_ready():
    try:
        db.session.execute(text("SELECT 1"))
        current_app.extensions["redis"].ping()
    except Exception:
        current_app.logger.warning("Admin readiness dependency check failed", exc_info=True)
        db.session.rollback()
        return jsonify({"status": "unavailable", "app_mode": "admin"}), 503
    return jsonify({"status": "ready", "app_mode": "admin"})


@admin_bp.route("/", methods=["GET", "POST"])
def index_disabled():
    session.clear()
    _audit_admin_denial("admin_access_denied", "fail_closed")
    return jsonify({"error": "Admin access is disabled pending strong authentication"}), 403


@admin_bp.route("/login", methods=["GET", "POST"])
@csrf.exempt
def login_disabled():
    session.clear()
    _audit_admin_denial("admin_login_disabled", "fail_closed")
    return jsonify({"error": "Admin login is disabled pending Phase 2 WebAuthn"}), 403


@admin_bp.route("/step-up", methods=["GET", "POST"])
@csrf.exempt
def step_up_disabled():
    session.clear()
    _audit_admin_denial("admin_step_up_disabled", "fail_closed")
    return jsonify({"error": "Admin step-up is disabled pending Phase 2 WebAuthn"}), 403
