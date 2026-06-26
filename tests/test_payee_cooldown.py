from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.banking.routes import _cooldown_status, _format_cooldown_remaining
from app.models import Payee


def test_payee_cooldown_status_uses_server_created_timestamp():
    created_at = datetime.now(timezone.utc) - timedelta(seconds=30)
    payee = Payee(
        user_id=1,
        nickname="Rent",
        account_number="123456789",
        recipient_name="Recipient",
        created_at=created_at,
    )

    status = _cooldown_status(payee, 12 * 60 * 60)

    assert status["status"] == "cooldown"
    assert status["remaining"].endswith("m")
    assert status["expires_at"] == (created_at + timedelta(hours=12)).isoformat()
    assert status["available_at"].endswith("UTC")


def test_payee_cooldown_status_marks_payee_active_after_cooldown():
    payee = Payee(
        user_id=1,
        nickname="Rent",
        account_number="123456789",
        recipient_name="Recipient",
        created_at=datetime.now(timezone.utc) - timedelta(seconds=61),
    )

    status = _cooldown_status(payee, 60)

    assert status == {
        "status": "active",
        "remaining": None,
        "expires_at": None,
        "available_at": None,
    }


def test_payee_cooldown_formatter_does_not_render_long_waits_as_minutes_only():
    assert _format_cooldown_remaining(12 * 60 * 60) == "12h 0m"
    assert _format_cooldown_remaining(24 * 60 * 60) == "1d 0h"
