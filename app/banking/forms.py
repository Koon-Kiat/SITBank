from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import InputRequired, Length, Regexp


ACCOUNT_NUMBER_RE = r"^[0-9]{9}$"
NICKNAME_RE = r"^[A-Za-z0-9 '\-]{1,64}$"


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
