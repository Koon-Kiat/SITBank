from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.auth import password_reset
from app.auth.services import AuthError
from app.security.rate_limits import AuthBackoffRequired


def test_reset_mfa_method_helpers_cover_legacy_and_invalid_values(monkeypatch):
    no_id = SimpleNamespace(id=None, mfa_enabled=False, mfa_step_up_preference=None)
    assert password_reset._legacy_passkey_credential_count(no_id) == 0
    assert password_reset._available_reset_mfa_methods_for_user(no_id) == []
    assert password_reset._fallback_reset_mfa_method([]) == password_reset.RESET_MFA_NONE
    assert password_reset._fallback_reset_mfa_method(
        [password_reset.RESET_MFA_MANUAL_RECOVERY]
    ) == password_reset.RESET_MFA_MANUAL_RECOVERY
    assert password_reset._available_reset_mfa_methods_from_transaction(
        {"available_mfa_methods": ["totp", "TOTP", "invalid", "manual_recovery"]}
    ) == ["totp", "manual_recovery"]
    assert password_reset._available_reset_mfa_methods_from_transaction(
        {"mfa_required": "invalid"}
    ) == []
    with pytest.raises(AuthError):
        password_reset._normalize_reset_mfa_method("invalid")
    assert password_reset._public_reset_mfa_method("manual_recovery") == (
        password_reset.RESET_MFA_MANUAL_RECOVERY
    )

    monkeypatch.setattr(
        password_reset,
        "_available_reset_mfa_methods_for_user",
        lambda _user: [password_reset.RESET_MFA_TOTP],
    )
    assert password_reset._mfa_requirement(
        SimpleNamespace(mfa_step_up_preference="totp")
    ) == password_reset.RESET_MFA_TOTP


def test_reset_token_helpers_fail_closed_for_every_reason(app, monkeypatch):
    now = datetime(2026, 1, 2, tzinfo=timezone.utc)
    user = SimpleNamespace(
        account_type="customer",
        username="customer",
        email="customer@example.test",
        is_frozen=False,
        security_locked_at=None,
    )
    base = {
        "used_at": None,
        "exchanged_at": None,
        "expires_at": now + timedelta(hours=1),
        "verifier_hmac": "expected",
    }
    monkeypatch.setattr(password_reset, "_token_hmac", lambda _verifier: "expected")

    assert password_reset._token_failure_reason(SimpleNamespace(**{**base, "used_at": now}), now, "v", user) == "reused"
    assert password_reset._token_failure_reason(
        SimpleNamespace(**{**base, "expires_at": now - timedelta(seconds=1)}),
        now,
        "v",
        user,
    ) == "expired"
    assert password_reset._token_failure_reason(SimpleNamespace(**base), now, "v", None) == "missing_user"
    assert password_reset._token_failure_reason(
        SimpleNamespace(**base),
        now,
        "v",
        SimpleNamespace(**{**user.__dict__, "account_type": "admin"}),
    ) == "admin_out_of_scope"
    assert password_reset._token_failure_reason(
        SimpleNamespace(**base),
        now,
        "v",
        SimpleNamespace(**{**user.__dict__, "is_frozen": True}),
    ) == "account_unavailable"
    assert password_reset._token_failure_reason(
        SimpleNamespace(**{**base, "verifier_hmac": "different"}),
        now,
        "v",
        user,
    ) == "invalid_verifier"
    assert password_reset._token_failure_reason(SimpleNamespace(**base), now, "v", user) == "invalid"

    for token in ("", "selector", ".verifier", "selector.", ("s" * 65) + ".v"):
        with pytest.raises(AuthError):
            password_reset._split_reset_token(token)
    assert password_reset._split_reset_token("selector.verifier") == (
        "selector",
        "verifier",
    )

    with app.app_context():
        assert password_reset._find_customer_user("   ") is None


@pytest.mark.parametrize(
    ("username", "email", "account_type", "expected"),
    [
        ("customer", "customer@example.test", "customer", False),
        ("admin", "customer@example.test", "customer", True),
        ("customer", "root@example.test", "customer", True),
        ("customer", "customer@admin.example.test", "customer", True),
        ("customer", "customer@example.test", "staff", True),
    ],
)
def test_admin_like_user_detection(username, email, account_type, expected):
    user = SimpleNamespace(
        username=username,
        email=email,
        account_type=account_type,
    )
    assert password_reset._is_admin_like_user(user) is expected


def test_reset_backoff_and_notification_failures_are_safely_audited(app, monkeypatch):
    audits = []
    monkeypatch.setattr(
        password_reset,
        "audit_event",
        lambda *args, **kwargs: audits.append((args, kwargs)),
    )
    monkeypatch.setattr(
        password_reset,
        "apply_exponential_backoff",
        lambda *_args: (_ for _ in ()).throw(AuthBackoffRequired(12)),
    )
    with pytest.raises(AuthError) as exc:
        password_reset._enforce_reset_backoff("reset", "principal")
    assert exc.value.retry_after == 12

    monkeypatch.setattr(
        password_reset,
        "send_recovery_code_used_notification",
        lambda _user: (_ for _ in ()).throw(RuntimeError("mail failed")),
    )
    with app.app_context():
        password_reset._send_recovery_code_used_notification(SimpleNamespace(id=1))
    assert audits[-1][0][:2] == ("recovery_code_notification", "failure")


def test_transaction_time_helpers_handle_invalid_and_naive_values(app, monkeypatch):
    with app.app_context():
        app.config["PASSWORD_RESET_TRANSACTION_TTL_SECONDS"] = 900
        assert password_reset._transaction_expires_in({"expires_at": "bad"}) == 900
    naive = datetime(2026, 1, 2, 3, 4, 5)
    assert password_reset._as_utc_datetime(naive).tzinfo == timezone.utc
    assert password_reset._utc_iso(naive).endswith("+00:00")
