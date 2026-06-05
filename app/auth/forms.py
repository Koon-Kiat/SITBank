from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import HiddenField, PasswordField, StringField
from wtforms.validators import Email, EqualTo, InputRequired, Length, Optional, Regexp

from app.security.passwords import PASSWORD_MIN_LENGTH

from .schemas import STEP_UP_TOKEN_RE, TOTP_RE, USERNAME_RE


class RegisterForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            InputRequired(),
            Length(min=3, max=64),
            Regexp(USERNAME_RE, message="Username contains invalid characters"),
        ],
    )
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=255)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=PASSWORD_MIN_LENGTH)])
    confirm_password = PasswordField(
        "Confirm password",
        validators=[
            InputRequired(),
            EqualTo("password", message="Passwords must match"),
        ],
    )


class LoginForm(FlaskForm):
    identifier = StringField("Username or email", validators=[InputRequired(), Length(max=255)])
    password = PasswordField("Password", validators=[InputRequired()])


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


class StepUpTokenForm(FlaskForm):
    stepup_token = HiddenField(
        validators=[
            Optional(),
            Regexp(STEP_UP_TOKEN_RE, message="Invalid security key step-up token"),
        ],
    )


class PasswordChangeForm(FlaskForm):
    current_password = PasswordField("Current password", validators=[InputRequired()])
    new_password = PasswordField("New password", validators=[InputRequired(), Length(min=PASSWORD_MIN_LENGTH)])
    confirm_new_password = PasswordField(
        "Confirm new password",
        validators=[
            InputRequired(),
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


class CsrfOnlyForm(FlaskForm):
    pass
