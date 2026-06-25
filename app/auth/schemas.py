from __future__ import annotations

from marshmallow import EXCLUDE, Schema, ValidationError, fields, validate, validates_schema

from app.security.passwords import PASSWORD_MIN_LENGTH, password_max_chars


USERNAME_RE = r"^[A-Za-z0-9_.-]{3,64}$"
FULL_NAME_RE = r"^[^\x00-\x1f\x7f<>]+$"
PHONE_RE = r"^[89][0-9]{7}$"
TOTP_RE = r"^[0-9]{6}$"
SESSION_REFERENCE_RE = r"^[A-Fa-f0-9]{32}$"
STEP_UP_TOKEN_RE = r"^[A-Za-z0-9_-]{32,256}$"
RESET_TOKEN_RE = r"^[A-Za-z0-9_-]{16,96}\.[A-Za-z0-9_-]{32,128}$"
REGISTRATION_OTP_RE = r"^[0-9]{6}$"


def password_length(*, minimum: int | None = None):
    def validate_password_length(value: str) -> bool:
        text = value or ""
        if minimum is not None and len(text) < minimum:
            raise ValidationError(f"Password must be at least {minimum} characters")
        max_chars = password_max_chars()
        if len(text) > max_chars:
            raise ValidationError(f"Password must be at most {max_chars} characters")
        return True

    return validate_password_length


class RegisterSchema(Schema):
    username = fields.Str(
        required=True,
        validate=[
            validate.Length(min=3, max=64),
            validate.Regexp(USERNAME_RE, error="Username contains invalid characters"),
        ],
    )
    full_name = fields.Str(
        required=True,
        validate=[
            validate.Length(min=1, max=120),
            validate.Regexp(FULL_NAME_RE, error="Full name contains invalid characters"),
        ],
    )
    phone_number = fields.Str(
        required=True,
        validate=validate.Regexp(PHONE_RE, error="Enter a valid Singapore phone number (8 digits starting with 8 or 9)"),
    )
    email = fields.Email(required=True, validate=validate.Length(max=255))
    password = fields.Str(
        required=True,
        load_only=True,
        validate=password_length(minimum=PASSWORD_MIN_LENGTH),
    )
    confirm_password = fields.Str(
        required=True,
        load_only=True,
        validate=password_length(minimum=PASSWORD_MIN_LENGTH),
    )

    @validates_schema
    def validate_password_match(self, data, **_kwargs):
        if data.get("password") != data.get("confirm_password"):
            raise ValidationError("Passwords must match")


class RegistrationOtpRequestSchema(Schema):
    email = fields.Email(required=True, validate=validate.Length(max=255))


class RegistrationOtpVerifySchema(Schema):
    email = fields.Email(required=True, validate=validate.Length(max=255))
    otp_code = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Regexp(REGISTRATION_OTP_RE, error="Verification code must be exactly 6 digits"),
    )


class LoginSchema(Schema):
    identifier = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    password = fields.Str(required=True, load_only=True, validate=validate.Length(min=1))


class ForgotPasswordSchema(Schema):
    email = fields.Email(required=True, validate=validate.Length(max=255))


class ManualRecoverySchema(Schema):
    identifier = fields.Str(required=True, validate=validate.Length(min=1, max=255))


class ResetTokenExchangeSchema(Schema):
    token = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Regexp(RESET_TOKEN_RE, error="Invalid reset token"),
    )


class TotpSchema(Schema):
    totp_code = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Regexp(TOTP_RE, error="MFA code must be exactly 6 digits"),
    )


class AuthenticationCodeSchema(Schema):
    totp_code = fields.Str(required=True, load_only=True, validate=validate.Length(min=1, max=80))


class PasswordResetMfaMethodSchema(Schema):
    method = fields.Str(
        required=True,
        validate=validate.OneOf(["totp", "authenticator"]),
    )


class TerminateSessionSchema(Schema):
    session_id = fields.Str(
        required=True,
        validate=[
            validate.Length(equal=32),
            validate.Regexp(SESSION_REFERENCE_RE, error="Invalid session reference"),
        ],
    )


class PasswordChangeSchema(Schema):
    current_password = fields.Str(required=True, load_only=True, validate=password_length(minimum=1))
    new_password = fields.Str(
        required=True,
        load_only=True,
        validate=password_length(minimum=PASSWORD_MIN_LENGTH),
    )
    confirm_new_password = fields.Str(
        required=True,
        load_only=True,
        validate=password_length(minimum=PASSWORD_MIN_LENGTH),
    )
    totp_code = fields.Str(
        required=False,
        load_only=True,
        validate=validate.Regexp(TOTP_RE, error="MFA code must be exactly 6 digits"),
    )
    stepup_token = fields.Str(
        required=False,
        load_only=True,
        validate=validate.Regexp(STEP_UP_TOKEN_RE, error="Invalid step-up token"),
    )
    @validates_schema
    def validate_password_match(self, data, **_kwargs):
        if data.get("new_password") != data.get("confirm_new_password"):
            raise ValidationError("Passwords must match")


class PasswordResetSchema(Schema):
    new_password = fields.Str(
        required=True,
        load_only=True,
    )
    confirm_new_password = fields.Str(
        required=True,
        load_only=True,
    )

    @validates_schema
    def validate_password_match(self, data, **_kwargs):
        if data.get("new_password") != data.get("confirm_new_password"):
            raise ValidationError("Passwords must match")


class HighRiskTotpSchema(Schema):
    class Meta:
        unknown = EXCLUDE

    totp_code = fields.Str(
        required=False,
        load_only=True,
        validate=validate.Regexp(TOTP_RE, error="MFA code must be exactly 6 digits"),
    )
    stepup_token = fields.Str(
        required=False,
        load_only=True,
        validate=validate.Regexp(STEP_UP_TOKEN_RE, error="Invalid step-up token"),
    )
