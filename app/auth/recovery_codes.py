from __future__ import annotations

import secrets
from datetime import datetime, timezone

from app.extensions import db
from app.models import RecoveryCode, User
from app.security.audit import audit_event
from app.security.email import send_security_email
from app.security.session_hmac import active_hmac_hex


RECOVERY_CODE_COUNT = 10
RECOVERY_CODE_LOW_THRESHOLD = 2
RECOVERY_CODE_RANDOM_BYTES = 16
RECOVERY_CODE_PURPOSE_TOTP = "totp_recovery"


def generate_recovery_codes_for_user(
    user: User,
    *,
    count: int = RECOVERY_CODE_COUNT,
    purpose: str = RECOVERY_CODE_PURPOSE_TOTP,
    commit: bool = True,
    audit: bool = True,
) -> list[str]:
    if count < 1 or count > 20:
        raise ValueError("Recovery code count must be between 1 and 20")

    now = _utcnow()
    db.session.execute(
        db.update(RecoveryCode)
        .where(
            RecoveryCode.user_id == user.id,
            RecoveryCode.purpose == purpose,
            RecoveryCode.used_at.is_(None),
        )
        .values(used_at=now)
    )

    codes = [_new_recovery_code() for _ in range(count)]
    for code in codes:
        db.session.add(
            RecoveryCode(
                user_id=user.id,
                code_hmac=_recovery_code_hmac(code),
                purpose=purpose,
            )
        )
    if commit:
        db.session.commit()
        if audit:
            audit_event("recovery_codes_generated", "success", user=user, metadata={"count": count, "purpose": purpose})
    return codes


def consume_recovery_code(user: User, code: str, *, purpose: str = RECOVERY_CODE_PURPOSE_TOTP) -> bool:
    result = db.session.execute(
        db.update(RecoveryCode)
        .where(
            RecoveryCode.user_id == user.id,
            RecoveryCode.code_hmac == _recovery_code_hmac(code),
            RecoveryCode.purpose == purpose,
            RecoveryCode.used_at.is_(None),
        )
        .values(used_at=_utcnow())
    )
    if result.rowcount != 1:
        db.session.rollback()
        return False
    db.session.commit()
    return True


def unused_recovery_code_count(user: User, *, purpose: str = RECOVERY_CODE_PURPOSE_TOTP) -> int:
    return int(
        db.session.execute(
            db.select(db.func.count(RecoveryCode.id)).where(
                RecoveryCode.user_id == user.id,
                RecoveryCode.purpose == purpose,
                RecoveryCode.used_at.is_(None),
            )
        ).scalar_one()
    )


def recovery_code_count_is_low(user: User, *, purpose: str = RECOVERY_CODE_PURPOSE_TOTP) -> bool:
    remaining = unused_recovery_code_count(user, purpose=purpose)
    return 0 <= remaining <= RECOVERY_CODE_LOW_THRESHOLD


def send_recovery_code_used_notification(user: User) -> None:
    body = (
        "A SITBank recovery code was used to complete authenticator MFA. "
        "If this was not you, contact support immediately. "
        "This message does not contain account recovery secrets."
    )
    send_security_email(user.email, "SITBank recovery code used", body)


def _recovery_code_hmac(code: str) -> str:
    return active_hmac_hex(f"recovery-code:{_normalize_recovery_code(code)}", length=64)


def _new_recovery_code() -> str:
    token = secrets.token_hex(RECOVERY_CODE_RANDOM_BYTES)
    return "-".join(token[index : index + 8] for index in range(0, len(token), 8))


def _normalize_recovery_code(code: str) -> str:
    return "".join(char for char in str(code or "").casefold() if char.isalnum())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)
