from __future__ import annotations

import re
from typing import Any

from flask import Blueprint, current_app, flash, g, jsonify, redirect, render_template, request, session, url_for
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm
from flask_wtf.csrf import generate_csrf
from marshmallow import Schema, ValidationError, fields, validate, validates_schema
from sqlalchemy import text
from wtforms import PasswordField, StringField
from wtforms.validators import Email, InputRequired, Length, Regexp

from app.extensions import db, limiter
from app.models import SecurityAuditEvent
from app.security.alerts import AlertConfigurationError, build_security_alert_report
from app.security.audit import audit_event
from app.security.production_guard import (
    is_production_app,
    log_production_readiness_failure,
    validate_production_security_prerequisites,
)
from app.security.rate_limits import request_principal
from app.security.turnstile import TurnstileError, require_turnstile

from .services import (
    ADMIN_INDEX_ENDPOINT,
    AuthError,
    admin_navigation_for,
    admin_dashboard_context,
    authenticate_admin_primary,
    complete_manual_recovery_request_as_admin,
    complete_admin_mfa_login,
    create_staff_invite,
    audit_event_detail_for_admin,
    query_audit_events_for_admin,
    invite_info,
    logout_admin_session,
    manual_recovery_requests_for_admin,
    public_invites_for_root_admin,
    public_admin_user,
    require_admin_session,
    require_root_admin_session,
    require_staff_session,
    revoke_staff_invite,
    staff_accounts_for_admin,
    start_invite_acceptance,
    transition_staff_account_as_root_admin,
    transition_manual_recovery_request_as_admin,
    verify_admin_totp_step_up,
    verify_invite_acceptance,
)


admin_bp = Blueprint("admin", __name__)

_TOTP_PATTERN = r"^[0-9]{6}$"
_MFA_CODE_ERROR = "MFA code must be exactly 6 digits"
_JSON_MIME_TYPE = "application/json"
_STAFF_ACCOUNTS_ENDPOINT = "admin.staff_accounts"
_ADMIN_LOGIN_TEMPLATE = "admin/login.html"
_ADMIN_MFA_VERIFY_TEMPLATE = "admin/mfa_verify.html"
_ALERT_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_ALERT_REDACTED_VALUE = "[redacted]"
_ALERT_SENSITIVE_VALUE_RE = re.compile(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]+")


class AdminLoginSchema(Schema):
    workplace_email = fields.Email(required=True, validate=validate.Length(max=255))
    password = fields.Str(required=True, load_only=True, validate=validate.Length(min=1))
    turnstile_token = fields.Str(required=False, load_only=True, allow_none=True)
    cf_turnstile_response = fields.Str(
        required=False,
        load_only=True,
        allow_none=True,
        data_key="cf-turnstile-response",
    )


class AdminTotpSchema(Schema):
    totp_code = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Regexp(_TOTP_PATTERN, error=_MFA_CODE_ERROR),
    )


class AdminLoginForm(FlaskForm):
    workplace_email = StringField(
        "Workplace email",
        validators=[InputRequired(), Email(), Length(max=255)],
    )
    password = PasswordField("Password", validators=[InputRequired()])


class AdminTotpForm(FlaskForm):
    totp_code = StringField(
        "Authenticator code",
        validators=[
            InputRequired(),
            Regexp(_TOTP_PATTERN, message=_MFA_CODE_ERROR),
        ],
    )


class StaffInviteCreateSchema(Schema):
    workplace_email = fields.Email(required=True, validate=validate.Length(max=255))
    role = fields.Str(required=True, validate=validate.OneOf(["staff", "admin"]))
    totp_code = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Regexp(_TOTP_PATTERN, error=_MFA_CODE_ERROR),
    )


class StaffInviteRevokeSchema(Schema):
    totp_code = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Regexp(_TOTP_PATTERN, error=_MFA_CODE_ERROR),
    )


class StaffAccountActionSchema(Schema):
    totp_code = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Regexp(_TOTP_PATTERN, error=_MFA_CODE_ERROR),
    )


class ManualRecoveryTransitionSchema(Schema):
    status = fields.Str(
        required=True,
        validate=validate.OneOf(["under_review", "approved", "denied"]),
    )
    reason = fields.Str(required=True, validate=validate.Length(min=1, max=512))
    totp_code = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Regexp(_TOTP_PATTERN, error=_MFA_CODE_ERROR),
    )


class ManualRecoveryCompleteSchema(Schema):
    reason = fields.Str(required=True, validate=validate.Length(min=1, max=512))
    totp_code = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Regexp(_TOTP_PATTERN, error=_MFA_CODE_ERROR),
    )


class StaffInviteStartSchema(Schema):
    full_name = fields.Str(required=True, validate=validate.Length(min=1, max=120))
    phone_number = fields.Str(required=True, validate=validate.Regexp(r"^[89][0-9]{7}$"))
    password = fields.Str(required=True, load_only=True)
    confirm_password = fields.Str(required=True, load_only=True)
    turnstile_token = fields.Str(required=False, load_only=True, allow_none=True)
    cf_turnstile_response = fields.Str(
        required=False,
        load_only=True,
        allow_none=True,
        data_key="cf-turnstile-response",
    )

    @validates_schema
    def validate_password_match(self, data, **_kwargs):
        if data.get("password") != data.get("confirm_password"):
            raise ValidationError("Passwords must match")


class StaffInviteVerifySchema(Schema):
    totp_code = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Regexp(_TOTP_PATTERN, error=_MFA_CODE_ERROR),
    )
    workplace_verification_code = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Regexp(_TOTP_PATTERN, error="Verification code must be exactly 6 digits"),
    )


@admin_bp.errorhandler(AuthError)
def handle_auth_error(error: AuthError):
    response = jsonify({"error": error.message})
    if error.retry_after is not None:
        response.headers["Retry-After"] = str(error.retry_after)
        response.headers["X-Auth-Retry-After"] = str(error.retry_after)
    return response, error.status_code


@admin_bp.errorhandler(ValidationError)
def handle_validation_error(_error: ValidationError):
    return jsonify({"error": "Invalid request"}), 400


@admin_bp.errorhandler(TurnstileError)
def handle_turnstile_error(_error: TurnstileError):
    return jsonify({"error": "Challenge verification failed"}), 400


def _payload(schema: Schema) -> dict:
    if request.is_json:
        return schema.load(request.get_json(silent=False) or {})
    payload = dict(request.form)
    payload.pop("csrf_token", None)
    return schema.load(payload)


def _request_fields() -> set[str]:
    if request.is_json:
        payload = request.get_json(silent=False) or {}
        return {str(key) for key in payload} if isinstance(payload, dict) else set()
    return {str(key) for key in request.form.keys()}


def _wants_json() -> bool:
    if request.is_json:
        return True
    best = request.accept_mimetypes.best_match([_JSON_MIME_TYPE, "text/html"])
    return best == _JSON_MIME_TYPE and (
        request.accept_mimetypes[_JSON_MIME_TYPE] >= request.accept_mimetypes["text/html"]
    )


def _safe_alert_text(value: Any, limit: int = 120) -> str:
    text = str(value or "").strip()
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text)
    compact = " ".join(text.split())[:limit]
    return _ALERT_REDACTED_VALUE if _ALERT_SENSITIVE_VALUE_RE.search(compact) else compact


def _alert_display_report(report: dict[str, Any], selected_ref: str | None) -> dict[str, Any]:
    display = dict(report)
    alerts = [
        _alert_display_item(alert, index)
        for index, alert in enumerate(report.get("alerts") or [])
        if isinstance(alert, dict)
    ]
    display["alerts"] = alerts
    display["highest_severity"] = _highest_alert_severity(alerts)
    display["next_action"] = _alert_next_action(display)
    display["selected_alert"] = next(
        (alert for alert in alerts if alert["ref"] == selected_ref),
        alerts[0] if alerts else None,
    )
    return display


def _alert_display_item(alert: dict[str, Any], index: int) -> dict[str, Any]:
    ref = f"alert-{index + 1}"
    event_id = _alert_existing_event_id(alert.get("latest_event_id"))
    return {
        "ref": ref,
        "detail_url": url_for("admin.alerts", alert=ref),
        "alert_type": _safe_alert_text(alert.get("alert_type"), 80),
        "severity": _safe_alert_text(alert.get("severity"), 24) or "low",
        "source": _safe_alert_text(alert.get("source"), 160) or "unknown",
        "count": int(alert.get("count") or 0),
        "window_seconds": int(alert.get("window_seconds") or 0),
        "generated_at": _safe_alert_text(alert.get("generated_at"), 40),
        "event_id": event_id,
        "event_url": url_for("admin.audit_log_detail", event_id=event_id) if event_id else "",
        "status": _safe_alert_text(alert.get("status"), 80),
        "reason": _safe_alert_text(alert.get("reason"), 120),
        "error_type": _safe_alert_text(alert.get("error_type"), 80),
        "recommended_action": _alert_recommended_action(alert),
    }


def _alert_existing_event_id(value: Any) -> int | None:
    try:
        event_id = int(value)
    except (TypeError, ValueError):
        return None
    if event_id <= 0:
        return None
    return event_id if db.session.get(SecurityAuditEvent, event_id) is not None else None


def _highest_alert_severity(alerts: list[dict[str, Any]]) -> str:
    if not alerts:
        return "none"
    return max(
        (alert["severity"] for alert in alerts),
        key=lambda severity: _ALERT_SEVERITY_RANK.get(str(severity).casefold(), 0),
    )


def _alert_next_action(report: dict[str, Any]) -> str:
    if int(report.get("alert_count") or 0) <= 0:
        return "No active alert findings. Continue scheduled monitoring."
    audit_chain = report.get("audit_chain") if isinstance(report.get("audit_chain"), dict) else {}
    if audit_chain and audit_chain.get("valid") is False:
        return "Preserve evidence and investigate audit-chain integrity before rotating anchors."
    database_integrity = (
        report.get("database_integrity")
        if isinstance(report.get("database_integrity"), dict)
        else {}
    )
    if database_integrity and database_integrity.get("valid") is False:
        return "Preserve database and host evidence before routine deployment or cleanup."
    return "Open the alert detail and correlate with safe audit-log entries."


def _alert_recommended_action(alert: dict[str, Any]) -> str:
    alert_type = str(alert.get("alert_type") or "").casefold()
    if "audit_anchor" in alert_type or "audit_chain" in alert_type:
        return "Stop routine anchor rotation, preserve the current anchor, and verify the hash chain."
    if "database_integrity" in alert_type:
        return "Preserve database state and compare the protected alert baseline before recovery."
    if "password_reset" in alert_type or "manual_recovery" in alert_type:
        return "Review related recovery audit events and rate-limit context before taking account action."
    if "login" in alert_type or "auth_backoff" in alert_type:
        return "Review related authentication audit events and source grouping."
    return "Review the safe audit detail and follow the incident response runbook."


def _safe_alert_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _alert_delivery_flags(report: dict[str, Any]) -> dict[str, Any]:
    delivery = report.get("delivery") if isinstance(report.get("delivery"), dict) else {}
    status_code = delivery.get("status_code")
    return {
        "attempted": bool(delivery.get("attempted")),
        "configured": bool(delivery.get("configured")),
        "enabled": bool(delivery.get("enabled")),
        "delivered": bool(delivery.get("delivered")) if "delivered" in delivery else None,
        "deduped": bool(delivery.get("deduped")),
        "provider": _safe_alert_text(delivery.get("provider"), 40),
        "status_code": int(status_code) if isinstance(status_code, int) and 100 <= status_code <= 599 else None,
        "error_type": _safe_alert_text(delivery.get("error_type"), 80),
    }


def _alert_dedupe_flags(report: dict[str, Any]) -> dict[str, Any]:
    dedupe = report.get("dedupe") if isinstance(report.get("dedupe"), dict) else {}
    return {
        "enabled": bool(dedupe.get("enabled")),
        "ttl_seconds": _safe_alert_int(dedupe.get("ttl_seconds")),
        "suppressed": _safe_alert_int(dedupe.get("suppressed")),
    }


def _alert_integrity_flags(value: Any) -> dict[str, Any]:
    status = value if isinstance(value, dict) else {}
    summary: dict[str, Any] = {}
    for key in ("checked", "valid", "configured", "anchor_configured", "anchor_validated", "state_path_configured"):
        if key in status:
            summary[key] = bool(status.get(key)) if status.get(key) is not None else None
    for key in ("event_count", "latest_event_id", "error_count", "anchor_error_count"):
        if key in status:
            summary[key] = _safe_alert_int(status.get(key))
    if status.get("error_type"):
        summary["error_type"] = _safe_alert_text(status.get("error_type"), 80)
    return summary


def _alert_delivery_outcome(report: dict[str, Any]) -> tuple[str, str]:
    alert_count = _safe_alert_int(report.get("alert_count"))
    deliverable_count = _safe_alert_int(report.get("deliverable_alert_count"))
    delivery = _alert_delivery_flags(report)
    dedupe = _alert_dedupe_flags(report)
    if alert_count <= 0:
        return "blocked", "no_active_alerts"
    if delivery["deduped"] or (deliverable_count <= 0 and dedupe["suppressed"] > 0):
        return "deduped", "dedupe_suppressed"
    if not delivery["enabled"]:
        return "blocked", "delivery_disabled"
    if not delivery["configured"]:
        return "blocked", "delivery_not_configured"
    if delivery["attempted"] and delivery["delivered"] is True:
        return "delivered", "delivery_sent"
    if delivery["attempted"] and delivery["delivered"] is False:
        return "failed", "delivery_failed"
    if deliverable_count <= 0:
        return "blocked", "no_deliverable_alerts"
    return "blocked", "delivery_not_attempted"


def _alert_delivery_metadata(
    report: dict[str, Any] | None = None,
    *,
    reason: str | None = None,
    error_type: str | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {"channel": "browser", "delivery_path": "build_security_alert_report"}
    if report is not None:
        delivery = _alert_delivery_flags(report)
        dedupe = _alert_dedupe_flags(report)
        metadata.update(
            {
                "alert_count": _safe_alert_int(report.get("alert_count")),
                "deliverable_alert_count": _safe_alert_int(report.get("deliverable_alert_count")),
                "delivery_attempted": delivery["attempted"],
                "delivery_configured": delivery["configured"],
                "delivery_enabled": delivery["enabled"],
                "dedupe_enabled": dedupe["enabled"],
                "dedupe_suppressed": dedupe["suppressed"],
            }
        )
        if delivery["error_type"]:
            metadata["error_type"] = delivery["error_type"]
    if reason:
        metadata["reason"] = _safe_alert_text(reason, 80)
    if error_type:
        metadata["error_type"] = _safe_alert_text(error_type, 80)
    return metadata


def _record_alert_delivery_event(
    actor: Any,
    outcome: str,
    report: dict[str, Any] | None = None,
    *,
    reason: str | None = None,
    error_type: str | None = None,
) -> None:
    audit_event(
        "security_alert_delivery",
        outcome,
        user=actor,
        metadata=_alert_delivery_metadata(report, reason=reason, error_type=error_type),
    )


def _alert_delivery_json_payload(report: dict[str, Any], outcome: str, reason: str) -> dict[str, Any]:
    safe_alerts = [
        _alert_display_item(alert, index)
        for index, alert in enumerate(report.get("alerts") or [])
        if isinstance(alert, dict)
    ]
    return {
        "message": "security_alert_delivery",
        "outcome": outcome,
        "reason": _safe_alert_text(reason, 80),
        "generated_at": _safe_alert_text(report.get("generated_at"), 40),
        "alert_count": _safe_alert_int(report.get("alert_count")),
        "deliverable_alert_count": _safe_alert_int(report.get("deliverable_alert_count")),
        "delivery": _alert_delivery_flags(report),
        "dedupe": _alert_dedupe_flags(report),
        "audit_chain": _alert_integrity_flags(report.get("audit_chain")),
        "database_integrity": _alert_integrity_flags(report.get("database_integrity")),
        "alerts": safe_alerts,
    }


def _alert_delivery_flash(outcome: str, reason: str) -> tuple[str, str]:
    if outcome == "delivered":
        return "Security alert delivery was sent through the configured channel.", "success"
    if outcome == "deduped":
        return "Security alert delivery was audited; existing dedupe suppressed repeat delivery.", "info"
    if outcome == "failed":
        return "Security alert delivery was audited, but delivery failed. Review the safe alert status.", "error"
    messages = {
        "delivery_disabled": "Security alert delivery is disabled.",
        "delivery_not_configured": "Security alert delivery is not configured.",
        "no_active_alerts": "No active alerts were available to deliver.",
        "no_deliverable_alerts": "No deliverable alerts were available.",
    }
    return messages.get(reason, "Security alert delivery was not sent."), "warning"


def _render_login_form(form: AdminLoginForm | None = None, *, status_code: int = 200):
    return render_template(_ADMIN_LOGIN_TEMPLATE, form=form or AdminLoginForm()), status_code


def _render_mfa_form(form: AdminTotpForm | None = None, *, status_code: int = 200):
    return render_template(_ADMIN_MFA_VERIFY_TEMPLATE, form=form or AdminTotpForm()), status_code


@admin_bp.get("/health/live")
def health_live():
    return jsonify({"status": "ok", "app_mode": "admin"})


@admin_bp.get("/health/ready")
def health_ready():
    if is_production_app(current_app):
        result = validate_production_security_prerequisites(current_app, app_mode="admin")
        if not result.ready:
            log_production_readiness_failure(current_app, result)
            return jsonify({"status": "unavailable", "app_mode": "admin"}), 503
        return jsonify({"status": "ready", "app_mode": "admin"})
    try:
        db.session.execute(text("SELECT 1"))
    except Exception:
        current_app.logger.warning("Admin readiness dependency check failed")
        db.session.rollback()
        return jsonify({"status": "unavailable", "app_mode": "admin"}), 503
    return jsonify({"status": "ready", "app_mode": "admin"})


@admin_bp.get("/csrf-token")
def csrf_token():
    return jsonify({"csrf_token": generate_csrf()})


@admin_bp.get("/")
def index():
    user = require_staff_session()
    if _wants_json():
        return jsonify({"message": "Admin access granted", "user": {"id": user.id, "role": user.account_type}})
    return render_template("admin/dashboard.html", **admin_dashboard_context(user))


@admin_bp.get("/login")
def login_form():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for(ADMIN_INDEX_ENDPOINT))
    if request.args.get("session_expired"):
        flash("Your admin session expired. Please log in again.", "warning")
    return _render_login_form()[0]


@admin_bp.post("/login")
@limiter.limit("50 per day", key_func=get_remote_address)
@limiter.limit("50 per day", key_func=request_principal)
@limiter.limit("5 per minute", key_func=get_remote_address)
@limiter.limit("5 per minute", key_func=request_principal)
def login():
    if _wants_json():
        data = _payload(AdminLoginSchema())
        require_turnstile("admin_login")
        return jsonify(authenticate_admin_primary(data["workplace_email"], data["password"]))

    form = AdminLoginForm()
    if not form.validate_on_submit():
        return _render_login_form(form, status_code=400)

    try:
        data = AdminLoginSchema().load(
            {
                "workplace_email": form.workplace_email.data,
                "password": form.password.data,
            }
        )
        require_turnstile("admin_login")
        authenticate_admin_primary(data["workplace_email"], data["password"])
    except ValidationError:
        flash("Invalid request", "error")
        return _render_login_form(form, status_code=400)
    except AuthError as exc:
        flash(exc.message, "error")
        return _render_login_form(form, status_code=exc.status_code)

    flash("Enter your authenticator code to finish signing in.", "info")
    return redirect(url_for("admin.mfa_verify_form")), 303


@admin_bp.get("/mfa/verify")
def mfa_verify_form():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for(ADMIN_INDEX_ENDPOINT))
    if not session.get("pending_mfa_user_id"):
        if _wants_json():
            return jsonify({"error": "No pending MFA challenge"}), 401
        flash("Please log in first.", "warning")
        return redirect(url_for("admin.login_form")), 303
    return _render_mfa_form()[0]


@admin_bp.post("/mfa/verify")
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=request_principal)
def mfa_verify():
    if _wants_json():
        data = _payload(AdminTotpSchema())
        return jsonify(complete_admin_mfa_login(data["totp_code"]))

    if not session.get("pending_mfa_user_id"):
        flash("Please log in first.", "warning")
        return redirect(url_for("admin.login_form")), 303

    form = AdminTotpForm()
    if not form.validate_on_submit():
        return _render_mfa_form(form, status_code=400)

    try:
        complete_admin_mfa_login(form.totp_code.data)
    except AuthError as exc:
        flash(exc.message, "error")
        return _render_mfa_form(form, status_code=exc.status_code)

    flash("Login successful.", "success")
    return redirect(url_for(ADMIN_INDEX_ENDPOINT)), 303


@admin_bp.post("/logout")
def logout():
    logout_admin_session()
    return jsonify({"message": "Logged out"})


@admin_bp.get("/invites")
def invites():
    actor = require_root_admin_session()
    payload = {"invites": public_invites_for_root_admin()}
    if _wants_json():
        return jsonify(payload)
    return render_template(
        "admin/invites.html",
        **payload,
        actor=actor,
        user=public_admin_user(actor),
        navigation=admin_navigation_for(actor),
    )


@admin_bp.post("/invites")
@limiter.limit("10 per hour", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=request_principal)
def invite_create():
    actor = require_root_admin_session()
    data = _payload(StaffInviteCreateSchema())
    result = create_staff_invite(
        actor,
        workplace_email=data["workplace_email"],
        role=data["role"],
        totp_code=data["totp_code"],
    )
    if _wants_json():
        return jsonify(result), 201
    flash("Staff/admin invite created.", "success")
    return redirect(url_for("admin.invites")), 303


@admin_bp.post("/invites/<int:invite_id>/revoke")
@limiter.limit("10 per hour", key_func=get_remote_address)
def invite_revoke(invite_id: int):
    actor = require_root_admin_session()
    data = _payload(StaffInviteRevokeSchema())
    result = revoke_staff_invite(actor, invite_id, data["totp_code"])
    if _wants_json():
        return jsonify(result)
    flash("Staff/admin invite revoked.", "success")
    return redirect(url_for("admin.invites")), 303


@admin_bp.get("/staff")
def staff_accounts():
    actor = require_admin_session()
    accounts = staff_accounts_for_admin(actor)
    if _wants_json():
        return jsonify({"accounts": accounts})
    return render_template(
        "admin/staff_accounts.html",
        accounts=accounts,
        actor=actor,
        user=public_admin_user(actor),
        navigation=admin_navigation_for(actor),
    )


@admin_bp.post("/staff/<int:user_id>/deactivate")
@limiter.limit("10 per hour", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=request_principal)
def staff_account_deactivate(user_id: int):
    actor = require_root_admin_session()
    data = _payload(StaffAccountActionSchema())
    result = transition_staff_account_as_root_admin(actor, user_id, "deactivate", data["totp_code"])
    if _wants_json():
        return jsonify(result)
    flash("Staff/admin account deactivated.", "success")
    return redirect(url_for(_STAFF_ACCOUNTS_ENDPOINT)), 303


@admin_bp.post("/staff/<int:user_id>/reactivate")
@limiter.limit("10 per hour", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=request_principal)
def staff_account_reactivate(user_id: int):
    actor = require_root_admin_session()
    data = _payload(StaffAccountActionSchema())
    result = transition_staff_account_as_root_admin(actor, user_id, "reactivate", data["totp_code"])
    if _wants_json():
        return jsonify(result)
    flash("Staff/admin account reactivated.", "success")
    return redirect(url_for(_STAFF_ACCOUNTS_ENDPOINT)), 303


@admin_bp.post("/staff/<int:user_id>/reset-activation")
@limiter.limit("10 per hour", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=request_principal)
def staff_account_reset_activation(user_id: int):
    actor = require_root_admin_session()
    data = _payload(StaffAccountActionSchema())
    result = transition_staff_account_as_root_admin(actor, user_id, "reset_activation", data["totp_code"])
    if _wants_json():
        return jsonify(result)
    flash("Staff/admin activation state reset.", "success")
    return redirect(url_for(_STAFF_ACCOUNTS_ENDPOINT)), 303


@admin_bp.get("/audit-logs")
def audit_logs():
    actor = require_admin_session()
    payload = query_audit_events_for_admin(actor, request.args.to_dict(flat=True))
    if _wants_json():
        return jsonify(payload)
    return render_template(
        "admin/audit_logs.html",
        **payload,
        actor=actor,
        user=public_admin_user(actor),
        navigation=admin_navigation_for(actor),
    )


@admin_bp.get("/audit-logs/<int:event_id>")
def audit_log_detail(event_id: int):
    actor = require_admin_session()
    event = audit_event_detail_for_admin(actor, event_id)
    if _wants_json():
        return jsonify({"event": event})
    return render_template(
        "admin/audit_log_detail.html",
        event=event,
        actor=actor,
        user=public_admin_user(actor),
        navigation=admin_navigation_for(actor),
    )


@admin_bp.get("/alerts")
def alerts():
    actor = require_admin_session()
    report = build_security_alert_report(deliver=False)

    audit_event(
        "security_alert_review",
        "success",
        user=actor,
        metadata={"alert_count": int(report.get("alert_count") or 0)},
    )
    if _wants_json():
        return jsonify(report)
    display_report = _alert_display_report(report, request.args.get("alert"))
    return render_template(
        "admin/alerts.html",
        report=display_report,
        delivery_form=AdminTotpForm(),
        actor=actor,
        user=public_admin_user(actor),
        navigation=admin_navigation_for(actor),
    )


@admin_bp.post("/alerts/deliver")
@limiter.limit("10 per hour", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=request_principal)
def alert_delivery():
    actor = require_admin_session()
    wants_json = _wants_json()
    if wants_json:
        data = _payload(AdminTotpSchema())
        totp_code = data["totp_code"]
    else:
        form = AdminTotpForm()
        if not form.validate_on_submit():
            _record_alert_delivery_event(actor, "blocked", reason="invalid_request")
            flash("Enter a current authenticator code.", "error")
            return redirect(url_for("admin.alerts")), 303
        totp_code = form.totp_code.data

    if not verify_admin_totp_step_up(actor, totp_code, "security_alert_delivery"):
        _record_alert_delivery_event(actor, "blocked", reason="invalid_totp_step_up")
        if wants_json:
            return jsonify({"error": "Fresh MFA verification is required"}), 403
        flash("Fresh MFA verification is required.", "error")
        return redirect(url_for("admin.alerts")), 303

    _record_alert_delivery_event(actor, "requested")
    try:
        report = build_security_alert_report(deliver=True)
    except AlertConfigurationError as exc:
        _record_alert_delivery_event(
            actor,
            "failed",
            reason="alert_configuration_error",
            error_type=type(exc).__name__,
        )
        if wants_json:
            return jsonify({"error": "Security alert delivery is unavailable"}), 503
        flash("Security alert delivery is unavailable.", "error")
        return redirect(url_for("admin.alerts")), 303

    outcome, reason = _alert_delivery_outcome(report)
    _record_alert_delivery_event(actor, outcome, report, reason=reason)
    if wants_json:
        status_code = 200 if outcome in {"delivered", "deduped", "blocked"} else 503
        return jsonify(_alert_delivery_json_payload(report, outcome, reason)), status_code

    message, category = _alert_delivery_flash(outcome, reason)
    flash(message, category)
    return redirect(url_for("admin.alerts")), 303


@admin_bp.get("/manual-recovery/requests")
def manual_recovery_requests():
    actor = require_root_admin_session()
    return jsonify({"requests": manual_recovery_requests_for_admin(actor)})


@admin_bp.post("/manual-recovery/requests/<int:request_id>/transition")
@limiter.limit("10 per hour", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=request_principal)
def manual_recovery_transition(request_id: int):
    actor = require_root_admin_session()
    data = _payload(ManualRecoveryTransitionSchema())
    return jsonify(
        transition_manual_recovery_request_as_admin(
            actor,
            request_id,
            data["status"],
            data["reason"],
            data["totp_code"],
        )
    )


@admin_bp.post("/manual-recovery/requests/<int:request_id>/complete")
@limiter.limit("10 per hour", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=request_principal)
def manual_recovery_complete(request_id: int):
    actor = require_root_admin_session()
    data = _payload(ManualRecoveryCompleteSchema())
    return jsonify(
        complete_manual_recovery_request_as_admin(
            actor,
            request_id,
            data["reason"],
            data["totp_code"],
        )
    )


@admin_bp.get("/invites/accept/<token>")
@limiter.limit("20 per hour", key_func=get_remote_address)
def invite_accept_info(token: str):
    return jsonify(invite_info(token))


@admin_bp.post("/invites/accept/<token>/start")
@limiter.limit("20 per hour", key_func=get_remote_address)
@limiter.limit("10 per 15 minutes", key_func=request_principal)
def invite_accept_start(token: str):
    data = _payload(StaffInviteStartSchema())
    return jsonify(
        start_invite_acceptance(
            token,
            full_name=data["full_name"],
            phone_number=data["phone_number"],
            password=data["password"],
            confirm_password=data["confirm_password"],
            turnstile_token=data.get("turnstile_token") or data.get("cf_turnstile_response"),
            request_fields=_request_fields(),
        )
    )


@admin_bp.post("/invites/accept/<token>/verify")
@limiter.limit("10 per 15 minutes", key_func=get_remote_address)
@limiter.limit("10 per 15 minutes", key_func=request_principal)
def invite_accept_verify(token: str):
    data = _payload(StaffInviteVerifySchema())
    return jsonify(
        verify_invite_acceptance(
            token,
            totp_code=data["totp_code"],
            workplace_verification_code=data["workplace_verification_code"],
            request_fields=_request_fields(),
        )
    )
