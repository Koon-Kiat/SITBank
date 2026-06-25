from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import generate_csrf
from marshmallow import Schema, ValidationError, fields, validate, validates_schema
from sqlalchemy import text

from app.extensions import db, limiter
from app.security.rate_limits import request_principal

from .services import (
    AuthError,
    authenticate_admin_primary,
    complete_admin_mfa_login,
    create_staff_invite,
    invite_info,
    logout_admin_session,
    public_invites_for_root_admin,
    require_root_admin_session,
    require_staff_session,
    revoke_staff_invite,
    start_invite_acceptance,
    verify_invite_acceptance,
)


admin_bp = Blueprint("admin", __name__)


class AdminLoginSchema(Schema):
    workplace_email = fields.Email(required=True, validate=validate.Length(max=255))
    password = fields.Str(required=True, load_only=True, validate=validate.Length(min=1))


class AdminTotpSchema(Schema):
    totp_code = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Regexp(r"^[0-9]{6}$", error="MFA code must be exactly 6 digits"),
    )


class StaffInviteCreateSchema(Schema):
    personal_email = fields.Email(required=True, validate=validate.Length(max=255))
    workplace_email = fields.Email(required=True, validate=validate.Length(max=255))
    role = fields.Str(required=True, validate=validate.OneOf(["staff", "admin"]))
    totp_code = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Regexp(r"^[0-9]{6}$", error="MFA code must be exactly 6 digits"),
    )


class StaffInviteRevokeSchema(Schema):
    totp_code = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Regexp(r"^[0-9]{6}$", error="MFA code must be exactly 6 digits"),
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
        validate=validate.Regexp(r"^[0-9]{6}$", error="MFA code must be exactly 6 digits"),
    )
    workplace_verification_code = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Regexp(r"^[0-9]{6}$", error="Verification code must be exactly 6 digits"),
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


@admin_bp.get("/health/live")
def health_live():
    return jsonify({"status": "ok", "app_mode": "admin"})


@admin_bp.get("/health/ready")
def health_ready():
    try:
        db.session.execute(text("SELECT 1"))
    except Exception:
        current_app.logger.warning("Admin readiness dependency check failed", exc_info=True)
        db.session.rollback()
        return jsonify({"status": "unavailable", "app_mode": "admin"}), 503
    return jsonify({"status": "ready", "app_mode": "admin"})


@admin_bp.get("/csrf-token")
def csrf_token():
    return jsonify({"csrf_token": generate_csrf()})


@admin_bp.get("/")
def index():
    user = require_staff_session()
    return jsonify({"message": "Admin access granted", "user": {"id": user.id, "role": user.account_type}})


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
    require_root_admin_session()
    return jsonify({"invites": public_invites_for_root_admin()})


@admin_bp.post("/invites")
@limiter.limit("10 per hour", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=request_principal)
def invite_create():
    actor = require_root_admin_session()
    data = _payload(StaffInviteCreateSchema())
    return jsonify(
        create_staff_invite(
            actor,
            personal_email=data["personal_email"],
            workplace_email=data["workplace_email"],
            role=data["role"],
            totp_code=data["totp_code"],
        )
    ), 201


@admin_bp.post("/invites/<int:invite_id>/revoke")
@limiter.limit("10 per hour", key_func=get_remote_address)
def invite_revoke(invite_id: int):
    actor = require_root_admin_session()
    data = _payload(StaffInviteRevokeSchema())
    return jsonify(revoke_staff_invite(actor, invite_id, data["totp_code"]))


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
