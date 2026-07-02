from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import HiddenField, PasswordField, StringField
from wtforms.validators import Email, EqualTo, InputRequired, Length, Optional, Regexp, ValidationError

from app.security.passwords import password_max_chars, password_min_length

from .schemas import FULL_NAME_RE, PHONE_RE, REGISTRATION_OTP_RE, STEP_UP_TOKEN_RE, TOTP_RE, USERNAME_RE


_INVALID_USERNAME_MESSAGE = "Username can only contain letters, numbers, underscores ( _ ), dots ( . ), and hyphens ( - )"
_PASSWORDS_MUST_MATCH_MESSAGE = "Passwords do not match. Please re-enter your password."
_INVALID_STEP_UP_TOKEN_MESSAGE = "Invalid step-up token"
_AUTHENTICATOR_CODE_LABEL = "Authenticator code"
_MFA_CODE_ERROR = "MFA code must be exactly 6 digits"
_VERIFICATION_CODE_ERROR = "Verification code must be exactly 6 digits"


def password_length(*, minimum: int | None = None):
    def validate_password_length(_form, field) -> None:
        value = field.data or ""
        min_chars = password_min_length() if minimum is None else minimum
        if len(value) < min_chars:
            raise ValidationError(f"Field must be at least {min_chars} characters long.")
        max_chars = password_max_chars()
        if len(value) > max_chars:
            raise ValidationError(f"Field cannot be longer than {max_chars} characters.")

    return validate_password_length


class RegisterForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            InputRequired(),
            Length(min=3, max=64),
            Regexp(USERNAME_RE, message=_INVALID_USERNAME_MESSAGE),
        ],
    )
    full_name = StringField(
        "Full name",
        validators=[
            InputRequired(),
            Length(min=1, max=120),
            Regexp(FULL_NAME_RE, message="Full name must contain only English letters, spaces, hyphens, and apostrophes"),
        ],
    )
    phone_number = StringField(
        "Phone number",
        validators=[
            InputRequired(),
            Regexp(PHONE_RE, message="Enter a valid Singapore phone number (8 digits starting with 8 or 9)"),
        ],
    )
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=255)])
    password = PasswordField("Password", validators=[InputRequired(), password_length()])
    confirm_password = PasswordField(
        "Confirm password",
        validators=[
            InputRequired(),
            password_length(),
            EqualTo("password", message=_PASSWORDS_MUST_MATCH_MESSAGE),
        ],
    )


class RegisterDetailsForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            InputRequired(),
            Length(min=3, max=64),
            Regexp(USERNAME_RE, message=_INVALID_USERNAME_MESSAGE),
        ],
    )
    full_name = StringField(
        "Full name",
        validators=[
            InputRequired(),
            Length(min=1, max=120),
            Regexp(FULL_NAME_RE, message="Full name must contain only English letters, spaces, hyphens, and apostrophes"),
        ],
    )
    phone_number = StringField(
        "Phone number",
        validators=[
            InputRequired(),
            Regexp(PHONE_RE, message="Enter a valid Singapore phone number (8 digits starting with 8 or 9)"),
        ],
    )
    password = PasswordField("Password", validators=[InputRequired(), password_length()])
    confirm_password = PasswordField(
        "Confirm password",
        validators=[
            InputRequired(),
            password_length(),
            EqualTo("password", message=_PASSWORDS_MUST_MATCH_MESSAGE),
        ],
    )


class RegistrationOtpRequestForm(FlaskForm):
    email = StringField("Customer email", validators=[InputRequired(), Email(), Length(max=255)])


class RegistrationOtpCodeForm(FlaskForm):
    otp_code = StringField(
        "Verification code",
        validators=[
            InputRequired(),
            Regexp(REGISTRATION_OTP_RE, message=_VERIFICATION_CODE_ERROR),
        ],
    )


class RegistrationOtpVerifyForm(FlaskForm):
    email = StringField("Customer email", validators=[InputRequired(), Email(), Length(max=255)])
    otp_code = StringField(
        "Verification code",
        validators=[
            InputRequired(),
            Regexp(REGISTRATION_OTP_RE, message=_VERIFICATION_CODE_ERROR),
        ],
    )


class LoginForm(FlaskForm):
    identifier = StringField("Username or email", validators=[InputRequired(), Length(max=255)])
    password = PasswordField("Password", validators=[InputRequired()])


class ForgotPasswordForm(FlaskForm):
    email = StringField("Email address", validators=[InputRequired(), Email(), Length(max=255)])


class ManualRecoveryForm(FlaskForm):
    identifier = StringField("Username or email", validators=[InputRequired(), Length(max=255)])


class ProfileForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            InputRequired(),
            Length(min=3, max=64),
            Regexp(USERNAME_RE, message=_INVALID_USERNAME_MESSAGE),
        ],
    )
    email = StringField("Email address", validators=[InputRequired(), Email(), Length(max=255)])
    email_verification_code = StringField(
        "Email verification code",
        validators=[
            Optional(),
            Regexp(REGISTRATION_OTP_RE, message=_VERIFICATION_CODE_ERROR),
        ],
    )
    totp_code = StringField(
        _AUTHENTICATOR_CODE_LABEL,
        validators=[
            Optional(),
            Regexp(TOTP_RE, message=_MFA_CODE_ERROR),
        ],
    )
    stepup_token = HiddenField(
        validators=[
            Optional(),
            Regexp(STEP_UP_TOKEN_RE, message=_INVALID_STEP_UP_TOKEN_MESSAGE),
        ],
    )


class TotpForm(FlaskForm):
    totp_code = StringField(
        "MFA code",
        validators=[
            InputRequired(),
            Regexp(TOTP_RE, message=_MFA_CODE_ERROR),
        ],
    )
    stepup_token = HiddenField(
        validators=[
            Optional(),
            Regexp(STEP_UP_TOKEN_RE, message=_INVALID_STEP_UP_TOKEN_MESSAGE),
        ],
    )


class AuthenticationCodeForm(FlaskForm):
    totp_code = StringField("Authentication code", validators=[InputRequired(), Length(max=80)])


class StepUpTokenForm(FlaskForm):
    stepup_token = HiddenField(
        validators=[
            Optional(),
            Regexp(STEP_UP_TOKEN_RE, message=_INVALID_STEP_UP_TOKEN_MESSAGE),
        ],
    )


class MfaOrStepUpForm(FlaskForm):
    totp_code = StringField(
        _AUTHENTICATOR_CODE_LABEL,
        validators=[
            Optional(),
            Regexp(TOTP_RE, message=_MFA_CODE_ERROR),
        ],
    )
    stepup_token = HiddenField(
        validators=[
            Optional(),
            Regexp(STEP_UP_TOKEN_RE, message=_INVALID_STEP_UP_TOKEN_MESSAGE),
        ],
    )


class PasswordChangeForm(FlaskForm):
    current_password = PasswordField("Current password", validators=[InputRequired(), password_length(minimum=1)])
    new_password = PasswordField("New password", validators=[InputRequired(), password_length()])
    confirm_new_password = PasswordField(
        "Confirm new password",
        validators=[
            InputRequired(),
            password_length(),
            EqualTo("new_password", message=_PASSWORDS_MUST_MATCH_MESSAGE),
        ],
    )
    totp_code = StringField(
        _AUTHENTICATOR_CODE_LABEL,
        validators=[
            Optional(),
            Regexp(TOTP_RE, message=_MFA_CODE_ERROR),
        ],
    )
    stepup_token = HiddenField(
        validators=[
            Optional(),
            Regexp(STEP_UP_TOKEN_RE, message=_INVALID_STEP_UP_TOKEN_MESSAGE),
        ],
    )


class PasswordResetForm(FlaskForm):
    new_password = PasswordField("New password", validators=[InputRequired()])
    confirm_new_password = PasswordField(
        "Confirm new password",
        validators=[
            InputRequired(),
            EqualTo("new_password", message=_PASSWORDS_MUST_MATCH_MESSAGE),
        ],
    )


class CsrfOnlyForm(FlaskForm):
    pass
