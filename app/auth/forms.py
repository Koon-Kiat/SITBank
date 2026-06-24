from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import HiddenField, PasswordField, SelectField, StringField
from wtforms.validators import Email, EqualTo, InputRequired, Length, Optional, Regexp, ValidationError

from app.security.passwords import PASSWORD_MIN_LENGTH, password_max_chars

from .schemas import PHONE_RE, STEP_UP_TOKEN_RE, TOTP_RE, USERNAME_RE


def password_length(*, minimum: int | None = None):
    def validate_password_length(_form, field) -> None:
        value = field.data or ""
        if minimum is not None and len(value) < minimum:
            raise ValidationError(f"Field must be at least {minimum} characters long.")
        max_chars = password_max_chars()
        if len(value) > max_chars:
            raise ValidationError(f"Field cannot be longer than {max_chars} characters.")

    return validate_password_length


class RegisterForm(FlaskForm):
    invite_token = HiddenField()
    username = StringField(
        "Username",
        validators=[
            InputRequired(),
            Length(min=3, max=64),
            Regexp(USERNAME_RE, message="Username contains invalid characters"),
        ],
    )
    full_name = StringField("Full name", validators=[InputRequired(), Length(min=1, max=120)])
    phone_number = StringField(
        "Phone number",
        validators=[
            InputRequired(),
            Regexp(PHONE_RE, message="Enter a valid Singapore phone number (8 digits starting with 8 or 9)"),
        ],
    )
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=255)])
    password = PasswordField("Password", validators=[InputRequired(), password_length(minimum=PASSWORD_MIN_LENGTH)])
    confirm_password = PasswordField(
        "Confirm password",
        validators=[
            InputRequired(),
            password_length(),
            EqualTo("password", message="Passwords must match"),
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
            Regexp(USERNAME_RE, message="Username contains invalid characters"),
        ],
    )
    email = StringField("Email address", validators=[InputRequired(), Email(), Length(max=255)])
    mfa_step_up_preference = SelectField(
        "Preferred verification",
        choices=[
            ("totp", "Authenticator code first"),
            ("passkey", "Passkey first"),
        ],
        validators=[InputRequired()],
    )
    totp_code = StringField(
        "Authenticator code",
        validators=[
            Optional(),
            Regexp(TOTP_RE, message="MFA code must be exactly 6 digits"),
        ],
    )
    stepup_token = HiddenField(
        validators=[
            Optional(),
            Regexp(STEP_UP_TOKEN_RE, message="Invalid security key step-up token"),
        ],
    )


class TotpForm(FlaskForm):
    totp_code = StringField(
        "MFA code",
        validators=[
            InputRequired(),
            Regexp(TOTP_RE, message="MFA code must be exactly 6 digits"),
        ],
    )
    stepup_token = HiddenField(
        validators=[
            Optional(),
            Regexp(STEP_UP_TOKEN_RE, message="Invalid security key step-up token"),
        ],
    )


class AuthenticationCodeForm(FlaskForm):
    totp_code = StringField("Authentication code", validators=[InputRequired(), Length(max=80)])


class StepUpTokenForm(FlaskForm):
    stepup_token = HiddenField(
        validators=[
            Optional(),
            Regexp(STEP_UP_TOKEN_RE, message="Invalid security key step-up token"),
        ],
    )


class MfaOrStepUpForm(FlaskForm):
    totp_code = StringField(
        "Authenticator code",
        validators=[
            Optional(),
            Regexp(TOTP_RE, message="MFA code must be exactly 6 digits"),
        ],
    )
    stepup_token = HiddenField(
        validators=[
            Optional(),
            Regexp(STEP_UP_TOKEN_RE, message="Invalid security key step-up token"),
        ],
    )


class PasswordChangeForm(FlaskForm):
    current_password = PasswordField("Current password", validators=[InputRequired(), password_length()])
    new_password = PasswordField("New password", validators=[InputRequired(), password_length(minimum=PASSWORD_MIN_LENGTH)])
    confirm_new_password = PasswordField(
        "Confirm new password",
        validators=[
            InputRequired(),
            password_length(),
            EqualTo("new_password", message="Passwords must match"),
        ],
    )
    totp_code = StringField(
        "Authenticator code",
        validators=[
            Optional(),
            Regexp(TOTP_RE, message="MFA code must be exactly 6 digits"),
        ],
    )
    stepup_token = HiddenField(
        validators=[
            Optional(),
            Regexp(STEP_UP_TOKEN_RE, message="Invalid security key step-up token"),
        ],
    )


class PasswordResetForm(FlaskForm):
    new_password = PasswordField("New password", validators=[InputRequired()])
    confirm_new_password = PasswordField(
        "Confirm new password",
        validators=[
            InputRequired(),
            EqualTo("new_password", message="Passwords must match"),
        ],
    )


class CsrfOnlyForm(FlaskForm):
    pass
