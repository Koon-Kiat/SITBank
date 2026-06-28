from __future__ import annotations

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import generate_csrf
from marshmallow import Schema, ValidationError, fields, validate, validates_schema
from sqlalchemy import text

from app.extensions import db, limiter
from app.security.alerts import build_security_alert_report
from app.security.production_guard import (
    is_production_app,
    log_production_readiness_failure,
    validate_production_security_prerequisites,
)
from app.security.rate_limits import request_principal

from .services import (
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
    verify_invite_acceptance,
)


admin_bp = Blueprint("admin", __name__)

_TOTP_PATTERN = r"^[0-9]{6}$"
_MFA_CODE_ERROR = "MFA code must be exactly 6 digits"
_JSON_MIME_TYPE = "application/json"
_STAFF_ACCOUNTS_ENDPOINT = "admin.staff_accounts"


class AdminLoginSchema(Schema):
    workplace_email = fields.Email(required=True, validate=validate.Length(max=255))
    password = fields.Str(required=True, load_only=True, validate=validate.Length(min=1))


class AdminTotpSchema(Schema):
    totp_code = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Regexp(_TOTP_PATTERN, error=_MFA_CODE_ERROR),
    )


class StaffInviteCreateSchema(Schema):
    personal_email = fields.Email(required=True, validate=validate.Length(max=255))
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


def _payload(schema: Schema) -> dict:
    if request.is_json:
        return schema.load(request.get_json(silent=False) or {})
    return schema.load(dict(request.form))


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


@admin_bp.post("/login")
@limiter.limit("50 per day", key_func=get_remote_address)
@limiter.limit("50 per day", key_func=request_principal)
@limiter.limit("5 per minute", key_func=get_remote_address)
@limiter.limit("5 per minute", key_func=request_principal)
def login():
    data = _payload(AdminLoginSchema())
    return jsonify(authenticate_admin_primary(data["workplace_email"], data["password"]))


@admin_bp.post("/mfa/verify")
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=request_principal)
def mfa_verify():
    data = _payload(AdminTotpSchema())
    return jsonify(complete_admin_mfa_login(data["totp_code"]))


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
        personal_email=data["personal_email"],
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
    from app.security.audit import audit_event

    audit_event(
        "security_alert_review",
        "success",
        user=actor,
        metadata={"alert_count": int(report.get("alert_count") or 0)},
    )
    if _wants_json():
        return jsonify(report)
    return render_template(
        "admin/alerts.html",
        report=report,
        actor=actor,
        user=public_admin_user(actor),
        navigation=admin_navigation_for(actor),
    )


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
            turnstile_token=data.get("turnstile_token"),
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
