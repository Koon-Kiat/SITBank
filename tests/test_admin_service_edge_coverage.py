from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.admin import services
from app.auth.services import AuthError


def test_email_normalizers_reject_malformed_and_aliased_addresses(app):
    with app.app_context():
        with pytest.raises(AuthError):
            services.normalize_workplace_email("not-an-email")
        with pytest.raises(AuthError):
            services.normalize_workplace_email(
                "staff+alias@sit.singaporetech.edu.sg",
            )
        with pytest.raises(AuthError):
            services.normalize_personal_email("not-an-email")


def test_invalid_invite_token_records_audited_failure(app, monkeypatch):
    reasons: list[tuple[str, bool]] = []
    monkeypatch.setattr(
        services,
        "_audit_invalid_invite_attempt",
        lambda reason, *, enabled: reasons.append((reason, enabled)),
    )

    with app.app_context(), pytest.raises(AuthError):
        services._active_invite_by_token("short", audit_failures=True)

    assert reasons == [("malformed_token", True)]


def test_admin_step_up_entry_points_reject_missing_totp(app, monkeypatch):
    actor = SimpleNamespace(id=42)
    monkeypatch.setattr(services, "is_root_admin", lambda _actor: True)
    monkeypatch.setattr(services, "audit_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        services,
        "_require_manual_recovery_reason",
        lambda reason, _event, _actor: reason,
    )

    with app.app_context():
        with pytest.raises(AuthError):
            services.create_staff_invite(
                actor,
                personal_email="staff@example.com",
                workplace_email="staff@sit.singaporetech.edu.sg",
                role="admin",
                totp_code=None,
            )
        with pytest.raises(AuthError):
            services.revoke_staff_invite(actor, 1, None)
        with pytest.raises(AuthError):
            services.complete_manual_recovery_request_as_admin(
                actor,
                1,
                "Identity verified",
                None,
            )
