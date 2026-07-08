from __future__ import annotations

from inspect import unwrap
from types import SimpleNamespace

from flask import g

from app.auth.services import AuthError
from app.web import routes


class _StubForm:
    def __init__(self, *, valid: bool = True):
        self._valid = valid
        self.totp_code = SimpleNamespace(data="123456")
        self.identifier = SimpleNamespace(data="alice01")
        self.reason = SimpleNamespace(data="")
        self.password = SimpleNamespace(data="old-password")
        self.email = SimpleNamespace(data="alice@example.com")
        self.current_password = SimpleNamespace(data="old-password")
        self.new_password = SimpleNamespace(data="new-password")
        self.confirm_new_password = SimpleNamespace(data="new-password")

    def validate_on_submit(self) -> bool:
        return self._valid


def _raise_auth_error(message: str = "denied", status_code: int = 403):
    def raiser(*_args, **_kwargs):
        raise AuthError(message, status_code)

    return raiser


def test_reset_dispatch_handles_expired_unknown_and_known_actions(app, monkeypatch):
    transaction = {"stage": "mfa"}

    with app.test_request_context(
        "/reset-password/continue",
        method="POST",
        data={"action": "verify_totp"},
    ):
        monkeypatch.setattr(routes, "current_reset_transaction", lambda: transaction)
        monkeypatch.setattr(
            routes,
            "_handle_reset_totp",
            lambda value: ("handled", value),
        )
        assert unwrap(routes.reset_password_continue_submit)() == (
            "handled",
            transaction,
        )

    with app.test_request_context(
        "/reset-password/continue",
        method="POST",
        data={"action": "unknown"},
    ):
        monkeypatch.setattr(
            routes,
            "_render_reset_continue",
            lambda value, *, status_code=200: (value, status_code),
        )
        assert unwrap(routes.reset_password_continue_submit)() == (transaction, 400)

    with app.test_request_context(
        "/reset-password/continue",
        method="POST",
        data={"action": "complete"},
    ):
        monkeypatch.setattr(
            routes,
            "current_reset_transaction",
            _raise_auth_error("expired", 401),
        )
        response = unwrap(routes.reset_password_continue_submit)()
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/forgot-password")


def test_reset_action_handlers_cover_validation_and_service_errors(app, monkeypatch):
    transaction = {"stage": "mfa"}
    rendered: list[tuple[dict, int]] = []

    def render(value, *, status_code=200):
        rendered.append((value, status_code))
        return value, status_code

    monkeypatch.setattr(routes, "_render_reset_continue", render)

    with app.test_request_context("/reset-password/continue", method="POST"):
        monkeypatch.setattr(routes, "AuthenticationCodeForm", lambda: _StubForm(valid=False))
        assert routes._handle_reset_totp(transaction) == (transaction, 400)

        monkeypatch.setattr(routes, "CsrfOnlyForm", lambda: _StubForm(valid=False))
        assert routes._handle_reset_mfa_selection(transaction) == (transaction, 400)

        monkeypatch.setattr(routes, "PasswordResetForm", lambda: _StubForm(valid=False))
        assert routes._handle_reset_completion(transaction) == (transaction, 400)

    with app.test_request_context(
        "/reset-password/continue",
        method="POST",
        data={"mfa_method": "totp"},
    ):
        monkeypatch.setattr(routes, "AuthenticationCodeForm", _StubForm)
        monkeypatch.setattr(routes, "verify_reset_totp", _raise_auth_error())
        assert routes._handle_reset_totp(transaction) == (transaction, 403)

        monkeypatch.setattr(routes, "CsrfOnlyForm", _StubForm)
        monkeypatch.setattr(routes, "select_reset_mfa_method", _raise_auth_error())
        assert routes._handle_reset_mfa_selection(transaction) == (transaction, 403)

        monkeypatch.setattr(routes, "PasswordResetForm", _StubForm)
        monkeypatch.setattr(routes, "complete_password_reset", _raise_auth_error())
        assert routes._handle_reset_completion(transaction) == (transaction, 403)

    assert rendered == [
        (transaction, 400),
        (transaction, 400),
        (transaction, 400),
        (transaction, 403),
        (transaction, 403),
        (transaction, 403),
    ]


def test_reset_action_handlers_cover_success_responses(app, monkeypatch):
    transaction = {"stage": "mfa"}
    verified = {"stage": "password"}
    rendered: list[tuple[dict, int]] = []

    def render(value, *, status_code=200):
        rendered.append((value, status_code))
        return value, status_code

    monkeypatch.setattr(routes, "_render_reset_continue", render)

    with app.test_request_context(
        "/reset-password/continue",
        method="POST",
        data={"mfa_method": "totp"},
    ):
        monkeypatch.setattr(routes, "AuthenticationCodeForm", _StubForm)
        monkeypatch.setattr(routes, "verify_reset_totp", lambda _code: verified)
        assert routes._handle_reset_totp(transaction) == (verified, 200)

        monkeypatch.setattr(routes, "CsrfOnlyForm", _StubForm)
        monkeypatch.setattr(routes, "select_reset_mfa_method", lambda _method: verified)
        assert routes._handle_reset_mfa_selection(transaction) == (verified, 200)

        monkeypatch.setattr(routes, "PasswordResetForm", _StubForm)
        monkeypatch.setattr(
            routes,
            "complete_password_reset",
            lambda _password, _confirmation: {
                "message": "Password reset.",
                "warnings": ["Review active sessions."],
            },
        )
        response = routes._handle_reset_completion(transaction)
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/login")

    assert rendered == [(verified, 200), (verified, 200)]


def test_mfa_dispatch_and_handlers_cover_invalid_requests(app, monkeypatch):
    forms = {
        "start": _StubForm(valid=False),
        "verify": _StubForm(valid=False),
        "replace_start": _StubForm(valid=False),
        "replace_verify": _StubForm(valid=False),
        "recovery_regenerate": _StubForm(valid=False),
    }
    rendered: list[int] = []

    def render(_forms, *, status_code=200, **_kwargs):
        rendered.append(status_code)
        return "mfa", status_code

    monkeypatch.setattr(routes, "_render_mfa_management", render)

    with app.test_request_context("/mfa/setup", method="POST"):
        g.current_user = SimpleNamespace(mfa_enabled=True)
        assert routes._handle_mfa_setup_start(forms) == ("mfa", 400)
        assert routes._handle_mfa_setup_verify(forms) == ("mfa", 400)
        assert routes._handle_mfa_replace_start(forms) == ("mfa", 400)
        assert routes._handle_mfa_replace_verify(forms) == ("mfa", 400)
        monkeypatch.setattr(routes, "CsrfOnlyForm", lambda: _StubForm(valid=False))
        assert routes._handle_recovery_code_regeneration(forms) == ("mfa", 400)

    assert rendered == [400, 400, 400, 400, 400]


def test_mfa_handlers_cover_service_errors(app, monkeypatch):
    forms = {
        "start": _StubForm(),
        "verify": _StubForm(),
        "replace_start": _StubForm(),
        "replace_verify": _StubForm(),
        "recovery_regenerate": _StubForm(),
    }

    monkeypatch.setattr(
        routes,
        "_render_mfa_management",
        lambda _forms, *, status_code=200, **_kwargs: ("mfa", status_code),
    )
    monkeypatch.setattr(routes, "generate_mfa_setup", _raise_auth_error())
    monkeypatch.setattr(routes, "verify_mfa_setup", _raise_auth_error())
    monkeypatch.setattr(routes, "generate_mfa_replacement", _raise_auth_error())
    monkeypatch.setattr(routes, "verify_mfa_replacement", _raise_auth_error())
    monkeypatch.setattr(routes, "regenerate_totp_recovery_codes", _raise_auth_error())
    monkeypatch.setattr(routes, "CsrfOnlyForm", _StubForm)

    with app.test_request_context("/mfa/setup", method="POST"):
        g.current_user = SimpleNamespace(mfa_enabled=True)

        response = routes._handle_mfa_setup_start(forms)
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/dashboard")
        assert routes._handle_mfa_setup_verify(forms) == ("mfa", 403)
        assert routes._handle_mfa_replace_start(forms) == ("mfa", 403)
        assert routes._handle_mfa_replace_verify(forms) == ("mfa", 403)
        assert routes._handle_recovery_code_regeneration(forms) == ("mfa", 403)


def test_mfa_dispatch_rejects_unknown_action(app, monkeypatch):
    with app.test_request_context(
        "/mfa/setup",
        method="POST",
        data={"action": "unknown"},
    ):
        g.current_user = SimpleNamespace(mfa_enabled=True)
        monkeypatch.setattr(routes, "_mfa_management_forms", lambda: {})
        response = unwrap(routes.mfa_setup_submit)()

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/mfa/setup")


def test_customer_guards_reject_privileged_users(app, monkeypatch):
    privileged_user = SimpleNamespace(is_frozen=False, security_locked_at=None)
    monkeypatch.setattr(routes, "is_customer_user", lambda _user: False)

    with app.test_request_context("/dashboard"):
        g.current_user = privileged_user
        response = routes.enforce_mfa_onboarding()
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/login")

    guarded = routes.web_login_required(lambda: "allowed")
    with app.test_request_context("/dashboard"):
        g.current_user = privileged_user
        routes.session["user_id"] = 42
        response = guarded()
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/login")


def test_public_auth_pages_redirect_authenticated_users(app):
    authenticated_user = SimpleNamespace()
    cases = (
        (routes.register_form, "/register", "GET"),
        (routes.register_otp_request, "/register/otp/request", "POST"),
        (routes.register_otp_verify, "/register/otp/verify", "POST"),
        (routes.register_submit, "/register", "POST"),
        (routes.login, "/login", "GET"),
        (routes.login_submit, "/login", "POST"),
        (routes.forgot_password, "/forgot-password", "GET"),
        (routes.account_recovery, "/account-recovery", "GET"),
        (routes.mfa_verify, "/mfa/verify", "GET"),
    )

    for view, path, method in cases:
        with app.test_request_context(path, method=method):
            g.current_user = authenticated_user
            response = unwrap(view)()
            assert response.status_code == 302
            assert response.headers["Location"].endswith("/dashboard")


def test_account_recovery_and_mfa_verify_response_paths(app, monkeypatch):
    monkeypatch.setattr(routes, "render_template", lambda *_args, **_kwargs: "rendered")

    with app.test_request_context("/account-recovery", method="POST"):
        g.current_user = None
        monkeypatch.setattr(routes, "ManualRecoveryForm", _StubForm)
        monkeypatch.setattr(
            routes,
            "request_manual_recovery",
            lambda _identifier, _reason: {"message": "Request accepted."},
        )
        response = unwrap(routes.account_recovery_submit)()
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/login")

    with app.test_request_context("/mfa/verify", method="POST"):
        g.current_user = None
        response = unwrap(routes.mfa_verify_submit)()
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/login")

    with app.test_request_context("/mfa/verify", method="POST"):
        g.current_user = None
        routes.session["pending_mfa_user_id"] = 42
        monkeypatch.setattr(
            routes,
            "AuthenticationCodeForm",
            lambda: _StubForm(valid=False),
        )
        assert unwrap(routes.mfa_verify_submit)() == ("rendered", 400)

        monkeypatch.setattr(routes, "AuthenticationCodeForm", _StubForm)
        monkeypatch.setattr(routes, "complete_pending_mfa", _raise_auth_error())
        assert unwrap(routes.mfa_verify_submit)() == ("rendered", 403)

        monkeypatch.setattr(routes, "complete_pending_mfa", lambda _code: None)
        response = unwrap(routes.mfa_verify_submit)()
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/dashboard")


def test_account_action_routes_cover_rejection_and_success_paths(app, monkeypatch):
    user = SimpleNamespace(is_frozen=False, security_locked_at=None)
    monkeypatch.setattr(routes, "render_template", lambda *_args, **_kwargs: "rendered")
    monkeypatch.setattr(routes, "has_enrolled_mfa_method", lambda _user: False)

    with app.test_request_context("/password/change", method="GET"):
        g.current_user = user
        response = unwrap(routes.password_change)()
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/mfa/setup")

    with app.test_request_context("/password/change", method="POST"):
        g.current_user = user
        response = unwrap(routes.password_change_submit)()
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/mfa/setup")

    monkeypatch.setattr(routes, "has_enrolled_mfa_method", lambda _user: True)
    monkeypatch.setattr(routes, "active_sessions_for_user", lambda _user: [])

    with app.test_request_context("/sessions/other/terminate", method="POST"):
        g.current_user = user
        monkeypatch.setattr(routes, "CsrfOnlyForm", lambda: _StubForm(valid=False))
        response = unwrap(routes.sessions_terminate_submit)("other")
        assert response.status_code == 302

        monkeypatch.setattr(routes, "CsrfOnlyForm", _StubForm)
        monkeypatch.setattr(routes, "terminate_session_for_user", _raise_auth_error())
        response, status_code = unwrap(routes.sessions_terminate_submit)("other")
        assert response.status_code == 302
        assert status_code == 403

        monkeypatch.setattr(
            routes,
            "terminate_session_for_user",
            lambda _user, _session_ref: None,
        )
        response = unwrap(routes.sessions_terminate_submit)("other")
        assert response.status_code == 302

    with app.test_request_context("/sessions/current/terminate", method="POST"):
        g.current_user = user
        monkeypatch.setattr(
            routes,
            "active_sessions_for_user",
            lambda _user: [{"current": True, "session_ref": "current"}],
        )
        response = unwrap(routes.sessions_terminate_submit)("current")
        assert response.status_code == 302

    with app.test_request_context("/sessions/revoke-others", method="POST"):
        g.current_user = user
        monkeypatch.setattr(routes, "MfaOrStepUpForm", lambda: _StubForm(valid=False))
        response = unwrap(routes.sessions_revoke_others_submit)()
        assert response.status_code == 302

        monkeypatch.setattr(routes, "MfaOrStepUpForm", _StubForm)
        monkeypatch.setattr(routes, "verify_high_risk_authorization", _raise_auth_error())
        response, status_code = unwrap(routes.sessions_revoke_others_submit)()
        assert response.status_code == 302
        assert status_code == 403

        monkeypatch.setattr(
            routes,
            "verify_high_risk_authorization",
            lambda *_args: None,
        )
        monkeypatch.setattr(routes, "terminate_other_sessions_for_user", lambda _user: 2)
        response = unwrap(routes.sessions_revoke_others_submit)()
        assert response.status_code == 302


def test_freeze_and_logout_validation_paths(app, monkeypatch):
    user = SimpleNamespace(is_frozen=False, security_locked_at=None)
    monkeypatch.setattr(routes, "render_template", lambda *_args, **_kwargs: "rendered")

    with app.test_request_context("/account/freeze", method="POST"):
        g.current_user = user
        monkeypatch.setattr(routes, "MfaOrStepUpForm", lambda: _StubForm(valid=False))
        assert unwrap(routes.freeze_account_submit)() == ("rendered", 400)

        monkeypatch.setattr(routes, "MfaOrStepUpForm", _StubForm)
        monkeypatch.setattr(routes, "freeze_own_account", _raise_auth_error())
        assert unwrap(routes.freeze_account_submit)() == ("rendered", 403)

    with app.test_request_context("/logout", method="POST"):
        monkeypatch.setattr(routes, "CsrfOnlyForm", lambda: _StubForm(valid=False))
        response = routes.logout()
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/")


def test_login_and_password_recovery_edge_responses(app, monkeypatch):
    monkeypatch.setattr(routes, "render_template", lambda *_args, **_kwargs: "rendered")

    with app.test_request_context("/login", method="POST"):
        g.current_user = None
        monkeypatch.setattr(routes, "LoginForm", lambda: _StubForm(valid=False))
        assert unwrap(routes.login_submit)() == ("rendered", 400)

        monkeypatch.setattr(routes, "LoginForm", _StubForm)
        monkeypatch.setattr(routes, "authenticate_primary", lambda *_args: {})
        response = unwrap(routes.login_submit)()
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/dashboard")

    with app.test_request_context("/forgot-password", method="POST"):
        g.current_user = None
        monkeypatch.setattr(routes, "ForgotPasswordForm", _StubForm)
        monkeypatch.setattr(
            routes,
            "request_password_reset",
            lambda _email: {"message": "If the account exists, instructions were sent."},
        )
        response = unwrap(routes.forgot_password_submit)()
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/login")

    with app.test_request_context("/reset-password?token=expired"):
        monkeypatch.setattr(routes, "exchange_reset_token", _raise_auth_error())
        response = unwrap(routes.reset_password_exchange)()
        assert response == "rendered"

    with app.test_request_context("/reset-password?token=expired", method="POST"):
        response = unwrap(routes.reset_password_exchange)()
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/forgot-password")

        monkeypatch.setattr(routes, "exchange_reset_token", lambda _token: None)
        response = unwrap(routes.reset_password_exchange)()
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/reset-password/continue")

    with app.test_request_context("/reset-password/continue"):
        monkeypatch.setattr(
            routes,
            "current_reset_transaction",
            _raise_auth_error("expired", 401),
        )
        response = routes.reset_password_continue()
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/forgot-password")
