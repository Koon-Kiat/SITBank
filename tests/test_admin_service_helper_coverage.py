from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.admin import services
from app.auth.services import AuthError
from app.security.identity_policy import IdentityPolicyError
from app.security.rate_limits import AuthBackoffRequired


def test_staff_identity_input_helpers_reject_unsafe_values(app, monkeypatch):
    with app.app_context():
        assert services.validate_full_name("  Valid Staff  ") == "Valid Staff"
        assert services.validate_phone_number(" 91234567 ") == "91234567"
        with pytest.raises(AuthError, match="Invalid full name"):
            services.validate_full_name("<invalid>")
        with pytest.raises(AuthError, match="Invalid phone number"):
            services.validate_phone_number("123")

        monkeypatch.setattr(
            services,
            "require_admin_workplace_email",
            lambda _email: (_ for _ in ()).throw(IdentityPolicyError("invalid")),
        )
        with pytest.raises(AuthError):
            services.normalize_workplace_email("invalid")
        monkeypatch.setattr(
            services,
            "require_admin_workplace_email",
            lambda _email: "alias+tag@sit.singaporetech.edu.sg",
        )
        with pytest.raises(AuthError):
            services.normalize_workplace_email("alias+tag@sit.singaporetech.edu.sg")

        with pytest.raises(AuthError):
            services.invite_token_hash("short")
        monkeypatch.setattr(services, "active_hmac_hex", lambda value, *, length: f"{length}:{value}")
        token = "a" * 32
        assert services.invite_token_hash(token) == f"64:staff-invite-token:{token}"


def test_invite_audit_email_and_workplace_code_helpers(app, monkeypatch):
    audits = []
    deliveries = []
    monkeypatch.setattr(
        services,
        "audit_event",
        lambda *args, **kwargs: audits.append((args, kwargs)),
    )
    monkeypatch.setattr(
        services,
        "send_security_email",
        lambda *args: deliveries.append(args),
    )
    invite = SimpleNamespace(
        id=7,
        token_hash="fake-token-hash",
        workplace_email_normalized="staff@sit.singaporetech.edu.sg",
        role="staff",
        status="pending",
        workplace_verification_code_hmac=None,
        workplace_verification_sent_at=None,
        workplace_verification_expires_at=None,
    )

    with app.app_context():
        services._audit_invalid_invite_attempt("missing", enabled=False)
        services._audit_invalid_invite_attempt("missing", enabled=True)
        assert len(audits) == 1

        services._send_invite_email(invite, "https://example.test/invite/fake")
        assert deliveries[-1][0] == invite.workplace_email_normalized

        monkeypatch.setattr(services.secrets, "randbelow", lambda _limit: 42)
        monkeypatch.setattr(
            services,
            "_utcnow",
            lambda: datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        monkeypatch.setattr(
            services,
            "_workplace_code_hmac",
            lambda _invite, code: f"hmac:{code}",
        )
        services._send_workplace_verification(invite)
        assert invite.workplace_verification_code_hmac == "hmac:000042"
        assert "000042" in deliveries[-1][2]

        assert services._verify_workplace_code(invite, "bad") is False
        invite.workplace_verification_code_hmac = None
        assert services._verify_workplace_code(invite, "000042") is False
        invite.workplace_verification_code_hmac = "hmac:000042"
        invite.workplace_verification_expires_at = datetime(2025, 1, 1, tzinfo=timezone.utc)
        assert services._verify_workplace_code(invite, "000042") is False
        invite.workplace_verification_expires_at = datetime(2027, 1, 1, tzinfo=timezone.utc)
        assert services._verify_workplace_code(invite, "000042") is True


def test_invite_request_and_manual_recovery_guard_helpers(app, monkeypatch):
    audits = []
    actor = SimpleNamespace(id=1)
    monkeypatch.setattr(
        services,
        "audit_event",
        lambda *args, **kwargs: audits.append((args, kwargs)),
    )
    with app.app_context():
        services._reject_forged_invite_fields({"full_name"})
        with pytest.raises(AuthError, match="Invalid request"):
            services._reject_forged_invite_fields({"role", "email"})
        assert audits[-1][1]["metadata"]["fields"] == ["email", "role"]

        with pytest.raises(AuthError, match="required"):
            services._require_manual_recovery_reason("", "manual", actor)
        with pytest.raises(AuthError, match="too long"):
            services._require_manual_recovery_reason("x" * 513, "manual", actor)
        assert services._require_manual_recovery_reason(" reviewed ", "manual", actor) == "reviewed"


def test_staff_database_duplicate_and_username_helpers(app, monkeypatch):
    class Result:
        def __init__(self, value):
            self.value = value

        def scalar_one_or_none(self):
            return self.value

    values = iter([object(), object(), object(), None])
    monkeypatch.setattr(
        services.db.session,
        "execute",
        lambda _statement: Result(next(values)),
    )
    with app.app_context():
        with pytest.raises(AuthError):
            services._reject_existing_staff_identity("staff@sit.singaporetech.edu.sg")
        with pytest.raises(AuthError):
            services._reject_duplicate_staff_signup(
                "staff@sit.singaporetech.edu.sg",
                "91234567",
            )
        with pytest.raises(AuthError):
            services._reject_active_invite("staff@sit.singaporetech.edu.sg")
        assert services._staff_username("Staff.Name@sit.singaporetech.edu.sg") == (
            "staff.Staff.Name"
        )


def test_mfa_payload_metadata_normalization_and_time_helpers(app, monkeypatch):
    user = SimpleNamespace(email="staff@sit.singaporetech.edu.sg")
    monkeypatch.setattr(
        services,
        "_totp",
        lambda _secret: SimpleNamespace(
            provisioning_uri=lambda *, name, issuer_name: f"otpauth://{issuer_name}/{name}"
        ),
    )
    monkeypatch.setattr(services, "_qr_data_uri", lambda uri: f"data:{uri}")
    monkeypatch.setattr(
        services,
        "audit_reference",
        lambda kind, value: f"{kind}:{value}",
    )
    invite = SimpleNamespace(
        id=7,
        workplace_email_normalized=user.email,
        role="staff",
        status="pending",
    )

    with app.app_context():
        payload = services._mfa_setup_payload(user, "fake-secret")
        assert payload["manual_entry_secret"] == "fake-secret"
        assert payload["qr_code_data_uri"].startswith("data:otpauth://")
        metadata = services._invite_audit_metadata(invite)
        assert metadata["invite_ref"] == "staff_invite:7"
        assert services._normalize_email(" User@EXAMPLE.TEST ") == "User@example.test"
        with pytest.raises(AuthError, match="Invalid email"):
            services._normalize_email("bad\nemail@example.test")
        assert services._contains_alias_separator("user+alias")
        assert not services._contains_alias_separator("user")

    naive = datetime(2026, 1, 2, 3, 4, 5)
    offset = datetime(2026, 1, 2, 11, 4, 5, tzinfo=timezone(timedelta(hours=8)))
    assert services._as_utc(naive).tzinfo == timezone.utc
    assert services._as_utc(offset) == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert services._utc_iso(naive).endswith("+00:00")


def test_active_invite_lookup_rejects_each_terminal_state(app, monkeypatch):
    now = datetime(2026, 1, 2, tzinfo=timezone.utc)
    audits = []
    commits = []

    class Result:
        def __init__(self, value):
            self.value = value

        def scalar_one_or_none(self):
            return self.value

    monkeypatch.setattr(services, "invite_token_hash", lambda _token: "fake-hash")
    monkeypatch.setattr(services, "_utcnow", lambda: now)
    monkeypatch.setattr(
        services,
        "_audit_invalid_invite_attempt",
        lambda reason, *, enabled: audits.append((reason, enabled)),
    )
    monkeypatch.setattr(services, "audit_event", lambda *args, **kwargs: audits.append(args))
    monkeypatch.setattr(services.db.session, "commit", lambda: commits.append(True))

    states = [
        (None, "missing"),
        (
            SimpleNamespace(
                expires_at=now - timedelta(seconds=1),
                status="pending",
                revoked_at=None,
                used_at=None,
                last_attempt_at=None,
                id=1,
                workplace_email_normalized="staff@sit.singaporetech.edu.sg",
                role="staff",
            ),
            "expired",
        ),
        (
            SimpleNamespace(
                expires_at=now + timedelta(hours=1),
                status="revoked",
                revoked_at=now,
                used_at=None,
                last_attempt_at=None,
            ),
            "revoked",
        ),
        (
            SimpleNamespace(
                expires_at=now + timedelta(hours=1),
                status="accepted",
                revoked_at=None,
                used_at=now,
                last_attempt_at=None,
            ),
            "used",
        ),
        (
            SimpleNamespace(
                expires_at=now + timedelta(hours=1),
                status="unknown",
                revoked_at=None,
                used_at=None,
                last_attempt_at=None,
            ),
            None,
        ),
    ]
    with app.app_context():
        for invite, reason in states:
            monkeypatch.setattr(
                services.db.session,
                "execute",
                lambda _statement, invite=invite: Result(invite),
            )
            with pytest.raises(AuthError):
                services._active_invite_by_token(
                    "a" * 32,
                    audit_failures=True,
                )
            if reason in {"missing", "revoked", "used"}:
                assert audits[-1] == (reason, True)
        assert commits == [True]

        active = SimpleNamespace(
            expires_at=now + timedelta(hours=1),
            status="pending",
            revoked_at=None,
            used_at=None,
            last_attempt_at=None,
        )
        monkeypatch.setattr(
            services.db.session,
            "execute",
            lambda _statement: Result(active),
        )
        assert services._active_invite_by_token("a" * 32) is active
        assert active.last_attempt_at == now


def test_invite_identity_and_auth_backoff_fail_closed(app, monkeypatch):
    invite = SimpleNamespace(
        id=1,
        workplace_email_normalized="invalid@example.test",
        role="staff",
        status="pending",
    )
    audits = []
    monkeypatch.setattr(
        services,
        "normalize_workplace_email",
        lambda _email: (_ for _ in ()).throw(AuthError("invalid", 400)),
    )
    monkeypatch.setattr(
        services,
        "audit_event",
        lambda *args, **kwargs: audits.append((args, kwargs)),
    )
    monkeypatch.setattr(
        services,
        "audit_reference",
        lambda kind, value: f"{kind}:{value}",
    )
    with app.app_context():
        with pytest.raises(AuthError):
            services._ensure_invite_identity_policy(invite, "invite")
        assert audits[-1][1]["metadata"]["reason"] == "email_policy"

        monkeypatch.setattr(
            services,
            "apply_exponential_backoff",
            lambda *_args: (_ for _ in ()).throw(AuthBackoffRequired(17)),
        )
        with pytest.raises(AuthError) as exc:
            services._enforce_auth_backoff("admin", "principal")
        assert exc.value.status_code == 429
        assert exc.value.retry_after == 17


def test_audit_filter_and_display_helpers_cover_safe_branching(app):
    filters = services._audit_filters(
        {
            "event_type": "login_success",
            "actor": "not-a-number",
            "target": "target_ref",
            "role": "staff",
            "severity": "high",
            "status": "success",
            "ip_address": "192.0.2.10",
            "correlation_id": "request_ref",
            "from": "bad-date",
            "to": "2026-01-02T03:04:05Z",
            "q": "123",
        }
    )
    assert filters["actor"] == ""
    assert services._parse_filter_datetime("") is None
    assert services._parse_filter_datetime("bad-date") is None
    assert services._parse_filter_datetime("2026-01-02T03:04:05Z") is not None
    assert services._bounded_int("bad", default=5, minimum=1, maximum=10) == 5
    assert services._bounded_int(100, default=5, minimum=1, maximum=10) == 10
    assert services._like_escape(r"a\b%c_d") == r"a\\b\%c\_d"

    statement = services.db.select(services.SecurityAuditEvent)
    assert services._apply_audit_actor_filter(statement, "") is statement
    assert services._apply_audit_actor_filter(statement, "bad") is statement
    assert services._apply_audit_actor_filter(statement, "12") is not statement
    assert services._apply_audit_search_filter(statement, "") is statement
    with app.app_context():
        assert services._apply_audit_search_filter(statement, "123") is not statement
    assert services._where_metadata_key_matches(
        statement,
        "severity",
        "high",
        exact=False,
    ) is not statement

    displayed = services._safe_metadata_for_display(
        {
            "count": 2,
            "items": ["safe", "Bearer fake-token"],
            "nested": {"safe": "value", "password": "fake"},
            "message": "safe text",
            "token": "fake",
        }
    )
    assert displayed["count"] == 2
    assert displayed["items"][1] == services.DISPLAY_REDACTED_VALUE
    assert displayed["nested"] == {"safe": "value"}
    assert "token" not in displayed
    assert services._safe_display_value("message", "", 20) == ""
    assert services._display_value_is_sensitive("password", "value")
    assert services._display_key_is_sensitive("principal_ref") is False
