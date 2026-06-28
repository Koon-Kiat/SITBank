from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import HiddenField, StringField
from wtforms.validators import InputRequired, Length, Optional, Regexp

from app.auth.schemas import STEP_UP_TOKEN_RE, TOTP_RE


ACCOUNT_NUMBER_RE = r"^[0-9]{9}$"
NICKNAME_RE = r"^[A-Za-z0-9 '\-]{1,64}$"
AMOUNT_RE = r"^\d+(\.\d{1,2})?$"
REFERENCE_RE = r"^[A-Za-z0-9 '\-.,/]{0,128}$"


class AddPayeeForm(FlaskForm):
    nickname = StringField(
        "Nickname",
        validators=[
            InputRequired(),
            Length(min=1, max=64),
            Regexp(
                NICKNAME_RE,
                message="Nickname may only contain letters, numbers, spaces, hyphens, and apostrophes",
            ),
        ],
    )
    account_number = StringField(
        "Account number",
        validators=[
            InputRequired(),
            Regexp(ACCOUNT_NUMBER_RE, message="Account number must be exactly 9 digits"),
        ],
    )
    totp_code = StringField(
        "Authenticator code",
        validators=[
            InputRequired(),
            Regexp(TOTP_RE, message="MFA code must be exactly 6 digits"),
        ],
    )
    stepup_token = HiddenField(
        validators=[
            Optional(),
            Regexp(STEP_UP_TOKEN_RE, message="Invalid step-up token"),
        ],
    )


class TransferForm(FlaskForm):
    amount = StringField(
        "Amount (SGD)",
        validators=[
            InputRequired(),
            Length(max=13),
            Regexp(AMOUNT_RE, message="Enter a valid amount (e.g. 10.00)"),
        ],
    )
    reference = StringField(
        "Reference (optional)",
        validators=[
            Optional(),
            Length(max=128),
            Regexp(
                REFERENCE_RE,
                message="Reference may only contain letters, numbers, spaces, and basic punctuation",
            ),
        ],
    )
    totp_code = StringField(
        "Authenticator code",
        validators=[
            InputRequired(),
            Regexp(TOTP_RE, message="MFA code must be exactly 6 digits"),
        ],
    )
    stepup_token = HiddenField(
        validators=[
            Optional(),
            Regexp(STEP_UP_TOKEN_RE, message="Invalid step-up token"),
        ],
    )
