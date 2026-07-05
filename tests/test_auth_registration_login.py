from __future__ import annotations

import json
from decimal import Decimal

from _auth_flow_helpers import *
from app.models import RegistrationCredit
from app.security.transaction_integrity import registration_credit_integrity_status


def test_registration_rejects_common_password(client):
    response = register(client, password="password")

    assert response.status_code == 400
    assert db.session.query(User).count() == 0


def test_account_number_generation_randomizes_all_twelve_positions(app, monkeypatch):
    from app.auth import services as auth_services

    digits = iter([9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8])
    monkeypatch.setattr(auth_services.secrets, "randbelow", lambda _limit: next(digits))

    assert auth_services._generate_account_number() == "987654321098"


@pytest.mark.parametrize(
    "invalid_account_number",
    ["123456789", "1234567890123", "12345678901x"],
)
def test_user_account_number_database_constraint_rejects_noncurrent_formats(
    app,
    invalid_account_number,
):
    from sqlalchemy.exc import IntegrityError

    user = User(
        username=f"invalid-{len(invalid_account_number)}-{invalid_account_number[-1]}",
        email=f"invalid-{len(invalid_account_number)}-{invalid_account_number[-1]}@example.test",
        password_hash="clearly-fake-password-hash",
        account_type="customer",
        account_status="active",
        full_name="Invalid Account Fixture",
        phone_number=None,
        account_number=invalid_account_number,
    )
    db.session.add(user)

    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_registration_uses_local_fallback_when_live_password_check_is_unavailable(client, monkeypatch):
    from app.security.passwords import HIBP_FALLBACK_WARNING, LivePasswordCheckUnavailable

    def unavailable(_password):
        raise LivePasswordCheckUnavailable("offline")

    monkeypatch.setattr("app.security.passwords._is_password_pwned_by_hibp", unavailable)
    verify_registration_email(client)

    response = client.post(
        "/register",
        data={
            "username": "alice01",
            "email": "alice@example.com",
            "full_name": "Alice Test",
            "phone_number": "91234567",
            "password": "correct horse battery staple",
            "confirm_password": "correct horse battery staple",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert db.session.query(User).count() == 1
    assert HIBP_FALLBACK_WARNING.encode("utf-8") in response.data


def test_registration_creates_single_welcome_credit_atomically(client):
    response = register(client)
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    credit = db.session.execute(
        db.select(RegistrationCredit).where(RegistrationCredit.user_id == user.id)
    ).scalar_one()

    assert response.status_code == 302
    assert Decimal(str(user.balance)) == Decimal("100.00")
    assert Decimal(str(credit.amount)) == Decimal("100.00")
    assert credit.status == "completed"
    assert registration_credit_integrity_status(credit) == "valid"
    assert db.session.query(RegistrationCredit).filter_by(user_id=user.id).count() == 1

def test_registration_rejects_live_breached_password(client, monkeypatch):
    monkeypatch.setattr("app.security.passwords._is_password_pwned_by_hibp", lambda _password: True)

    response = register(client)

    assert response.status_code == 400
    assert db.session.query(User).count() == 0
    assert b"Password is too common. Please try again" in response.data

def test_register_requires_verified_customer_email(client):
    response = register(client, verify_email=False)

    assert response.status_code == 400
    assert b"Please verify your email address before continuing" in response.data
    assert db.session.query(User).count() == 0


def test_registration_step_one_has_single_email_input(client):
    response = client.get("/register")
    html = response.data.decode("utf-8")

    assert response.status_code == 200
    assert "data-otp-request-form" in html
    assert html.count('name="email"') == 1
    assert "Complete your account" not in html
    assert "data-password-strength" not in html


def test_registration_step_two_uses_verified_email_text_not_input(client):
    verify_registration_email(client, "verified@example.com")

    response = client.get("/register")
    html = response.data.decode("utf-8")

    assert response.status_code == 200
    assert "Complete your account" in html
    assert "Your email is verified" in html
    assert "verified@example.com" in html
    assert 'name="email"' not in html
    assert "data-password-strength" in html


def test_registration_ignores_forged_step_two_email_field(client):
    verify_registration_email(client, "verified@example.com")

    response = client.post(
        "/register",
        data={
            "username": "verified01",
            "email": "attacker@example.com",
            "email_verified": "true",
            "full_name": "Verified User",
            "phone_number": "91234567",
            "password": "correct horse battery staple",
            "confirm_password": "correct horse battery staple",
        },
    )
    user = db.session.execute(db.select(User).where(User.username == "verified01")).scalar_one()

    assert response.status_code == 302
    assert user.email == "verified@example.com"


def test_registration_consumes_verified_email_after_success(client):
    verify_registration_email(client, "consume@example.com")

    created = client.post(
        "/register",
        data={
            "username": "consume01",
            "full_name": "Consume User",
            "phone_number": "91234567",
            "password": "correct horse battery staple",
            "confirm_password": "correct horse battery staple",
        },
    )
    reused = client.post(
        "/register",
        data={
            "username": "consume02",
            "full_name": "Consume User Two",
            "phone_number": "91234568",
            "password": "correct horse battery staple",
            "confirm_password": "correct horse battery staple",
        },
    )

    assert created.status_code == 302
    assert reused.status_code == 400
    assert b"Please verify your email address before continuing" in reused.data
    assert db.session.query(User).count() == 1


def test_registration_otp_allows_personal_customer_email(client):
    response = client.post("/auth/register/otp/request", json={"email": "alice@example.com"})

    assert response.status_code == 200
    assert response.get_json() == {"message": "Check your inbox. If this address is valid, a verification code has been sent."}
    assert db.session.query(User).count() == 0


def test_registration_otp_rejects_admin_and_root_allowlist_emails(client):
    cases = [
        ("staff@sit.singaporetech.edu.sg", "admin_email_domain"),
        ("staff@singaporetech.edu.sg", "admin_email_domain"),
        ("root1@sit.singaporetech.edu.sg", "root_admin_allowlisted_email"),
    ]
    responses = [
        client.post("/auth/register/otp/request", json={"email": email})
        for email, _reason in cases
    ]
    events = db.session.query(SecurityAuditEvent).filter_by(event_type="registration_otp").all()

    assert [response.status_code for response in responses] == [400, 400, 400]
    assert [response.get_json() for response in responses] == [
        {"error": "Registration could not be started for that email."},
        {"error": "Registration could not be started for that email."},
        {"error": "Registration could not be started for that email."},
    ]
    assert [event.outcome for event in events] == ["blocked", "blocked", "blocked"]
    assert {event.event_metadata["reason"] for event in events} == {reason for _email, reason in cases}


def test_registration_otp_uses_exact_admin_domain_matching(client):
    response = client.post(
        "/auth/register/otp/request",
        json={"email": "alice@sit.singaporetech.edu.sg.example.com"},
    )

    assert response.status_code == 200
    assert response.get_json() == {"message": "Check your inbox. If this address is valid, a verification code has been sent."}


def test_registration_service_rechecks_customer_email_policy(client):
    with client.session_transaction() as sess:
        sess[REGISTRATION_OTP_VERIFIED_EMAIL_KEY] = "root1@sit.singaporetech.edu.sg"
        sess[REGISTRATION_OTP_VERIFIED_AT_KEY] = int(time.time())

    response = client.post(
        "/auth/register",
        json={
            "username": "root-as-customer",
            "email": "root1@sit.singaporetech.edu.sg",
            "full_name": "Root As Customer",
            "phone_number": "91234567",
            "password": "correct horse battery staple",
            "confirm_password": "correct horse battery staple",
        },
    )
    events = db.session.query(SecurityAuditEvent).filter_by(event_type="registration").all()

    assert response.status_code == 400
    assert response.get_json() == {"error": "Please verify your email address before continuing."}
    assert db.session.query(User).count() == 0
    assert events[-1].outcome == "blocked"
    assert events[-1].event_metadata["reason"] == "root_admin_allowlisted_email"


def test_registration_otp_hashes_code_and_verifies_email(client):
    from app.security.email import password_reset_outbox
    from app.models import RegistrationOtpChallenge

    email = "alice@example.com"
    request_response = client.post("/auth/register/otp/request", json={"email": email})
    raw_code = re.search(r"\b([0-9]{6})\b", password_reset_outbox()[-1]["body"]).group(1)
    stored_values = [
        challenge.otp_hmac
        for challenge in db.session.execute(db.select(RegistrationOtpChallenge)).scalars()
    ]
    verify_response = client.post("/auth/register/otp/verify", json={"email": email, "otp_code": raw_code})

    assert request_response.status_code == 200
    assert verify_response.status_code == 200
    assert password_reset_outbox()[-1]["to"] == "alice@example.com"
    assert password_reset_outbox()[-1]["subject"] == "SITBank registration verification code"
    assert stored_values
    assert all(raw_code not in str(value) for value in stored_values)


def test_registration_otp_resend_invalidates_previous_code(client, monkeypatch):
    from app.security.email import password_reset_outbox

    email = "alice@example.com"
    first = client.post("/auth/register/otp/request", json={"email": email})
    first_code = re.search(r"\b([0-9]{6})\b", password_reset_outbox()[-1]["body"]).group(1)
    resend_time = int(time.time()) + 61
    monkeypatch.setattr("app.auth.registration_otp.time.time", lambda: resend_time)
    second = client.post("/auth/register/otp/request", json={"email": email})
    second_code = re.search(r"\b([0-9]{6})\b", password_reset_outbox()[-1]["body"]).group(1)
    old_code_verify = client.post("/auth/register/otp/verify", json={"email": email, "otp_code": first_code})
    new_code_verify = client.post("/auth/register/otp/verify", json={"email": email, "otp_code": second_code})

    assert first.status_code == 200
    assert second.status_code == 200
    assert first_code != second_code
    assert old_code_verify.status_code == 400
    assert new_code_verify.status_code == 200


def test_registration_otp_attempt_limit_invalidates_code(client):
    from app.security.email import password_reset_outbox

    email = "alice@example.com"
    client.post("/auth/register/otp/request", json={"email": email})
    code = re.search(r"\b([0-9]{6})\b", password_reset_outbox()[-1]["body"]).group(1)
    failures = [
        client.post("/auth/register/otp/verify", json={"email": email, "otp_code": "000000"})
        for _ in range(5)
    ]
    valid_after_lock = client.post("/auth/register/otp/verify", json={"email": email, "otp_code": code})

    assert [response.status_code for response in failures] == [400, 400, 400, 400, 400]
    assert valid_after_lock.status_code == 400


def test_registration_otp_existing_account_response_is_generic(client):
    from app.security.email import password_reset_outbox

    created = register(client)
    before_count = len(password_reset_outbox())
    second_client = current_app.test_client()
    response = second_client.post(
        "/auth/register/otp/request",
        json={"email": "alice@example.com"},
    )

    assert created.status_code == 302
    assert response.status_code == 200
    assert response.get_json() == {"message": "Check your inbox. If this address is valid, a verification code has been sent."}
    assert len(password_reset_outbox()) == before_count


def test_registration_otp_email_failure_fails_closed_without_code(client, monkeypatch):
    from app.models import RegistrationOtpChallenge

    def fail_delivery(*_args, **_kwargs):
        raise RuntimeError("smtp secret should not leak")

    monkeypatch.setattr("app.auth.registration_otp.send_security_email", fail_delivery)

    response = client.post(
        "/auth/register/otp/request",
        json={"email": "alice@example.com"},
    )

    assert response.status_code == 503
    assert response.get_json() == {"error": "Could not send a code right now. Please try again in a moment."}
    assert db.session.query(RegistrationOtpChallenge).count() == 0


def test_registration_otp_audit_events_do_not_store_codes(client):
    from app.security.email import password_reset_outbox

    request_response, verify_response = verify_registration_email(client)
    otp_code = re.search(r"\b([0-9]{6})\b", password_reset_outbox()[-1]["body"]).group(1)
    events = db.session.query(SecurityAuditEvent).filter_by(event_type="registration_otp").all()
    metadata_json = json.dumps([event.event_metadata for event in events])

    assert request_response.status_code == 200
    assert verify_response.status_code == 200
    assert {event.outcome for event in events} == {"requested", "verified"}
    assert otp_code not in metadata_json
    assert "otp" not in metadata_json.casefold()


def test_registration_invite_cli_commands_are_removed(app):
    for command in (
        "create-registration-invite",
        "create-registration-invites",
        "list-registration-invites",
        "revoke-registration-invite",
    ):
        result = app.test_cli_runner().invoke(args=[command])
        assert result.exit_code != 0
        assert "No such command" in result.output


def test_email_otp_registration_preserves_mfa_onboarding(client):
    created = register(client)
    login_response = login(client)

    assert created.status_code == 302
    assert login_response.status_code == 302
    assert login_response.headers["Location"].endswith("/mfa/setup")

def test_registration_hashes_password_with_pbkdf2(client):
    response = register(client)

    assert response.status_code == 302
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    assert user.account_number is not None
    assert len(user.account_number) == 12
    assert user.account_number.isascii()
    assert user.account_number.isdigit()
    assert user.account_number.isdigit()
    assert not user.password_hash.endswith("correct horse battery staple")
    assert user.password_hash.startswith(f"{PBKDF2_PREFIX}$v1$i=600000$")

def test_short_password_registration_retry_can_login(client):
    rejected = register(client, username="retry01", email="retry@example.com", password="short")
    created = register(client, username="retry01", email="retry@example.com")
    login_response = login(client, identifier="retry01")
    dashboard_response = client.get("/dashboard")

    assert rejected.status_code == 400
    assert created.status_code == 302
    assert created.headers["Location"].endswith("/login")
    assert login_response.status_code == 302
    assert login_response.headers["Location"].endswith("/mfa/setup")
    assert dashboard_response.status_code == 302
    assert dashboard_response.headers["Location"].endswith("/mfa/setup")

def test_long_unicode_password_can_register_login_and_change(client, monkeypatch):
    long_password = "correct horse battery staple " + ("安全な合言葉" * 12)
    new_password = long_password + " updated"

    response = register(client, password=long_password)
    login_response = login(client, password=long_password)
    user, secret = enable_mfa_for_user()
    old_hash = user.password_hash
    change_time = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: change_time)

    change_response = client.post(
        "/password/change",
        data={
            "current_password": long_password,
            "new_password": new_password,
            "confirm_new_password": new_password,
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(change_time),
        },
    )
    db.session.refresh(user)

    assert response.status_code == 302
    assert login_response.status_code == 302
    assert change_response.status_code == 302
    assert user.password_hash != old_hash
    assert verify_password(new_password, user.password_hash)

def test_password_templates_do_not_truncate_and_show_max_length_guidance(client):
    verify_registration_email(client, "template@example.com")
    register_response = client.get("/register")
    login_response = client.get("/login")
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    change_response = client.get("/password/change")

    assert register_response.status_code == 200
    assert login_response.status_code == 200
    assert change_response.status_code == 200
    assert len(password_inputs(register_response)) == 2
    assert len(password_inputs(login_response)) == 1
    assert len(password_inputs(change_response)) == 3
    assert all(b"maxlength" not in field for field in password_inputs(register_response))
    assert all(b"maxlength" not in field for field in password_inputs(login_response))
    assert all(b"maxlength" not in field for field in password_inputs(change_response))
    expected_guidance = (
        f"Use {PASSWORD_MIN_LENGTH} to {PASSWORD_MAX_CHARS} characters. "
        f"{PASSWORD_RECOMMENDED_MIN_LENGTH} or more is recommended."
    ).encode("utf-8")
    assert expected_guidance in register_response.data
    assert b"Maximum password length is 256 characters." not in login_response.data
    assert expected_guidance in change_response.data
    assert b"Maximum password length is 256 characters." in change_response.data

def test_password_at_minimum_length_can_register_and_login(client):
    password = "Abcdef12"

    response = register(client, password=password)
    login_response = login(client, password=password)

    assert len(password) == PASSWORD_MIN_LENGTH
    assert response.status_code == 302
    assert login_response.status_code == 302
    assert db.session.query(User).count() == 1


def test_browser_registration_uses_configured_password_minimum(app, client):
    app.config["PASSWORD_MIN_LENGTH"] = 12
    verify_registration_email(client, "minimum@example.com")

    too_short = client.post(
        "/register",
        data={
            "username": "minimum01",
            "full_name": "Minimum Test",
            "phone_number": "91234567",
            "password": "Abcdef12345",
            "confirm_password": "Abcdef12345",
        },
        follow_redirects=False,
    )

    assert too_short.status_code == 400
    assert b"Field must be at least 12 characters long." in too_short.data
    assert db.session.query(User).count() == 0

    accepted_password = "Abcdef123456"
    response = client.post(
        "/register",
        data={
            "username": "minimum01",
            "full_name": "Minimum Test",
            "phone_number": "91234567",
            "password": accepted_password,
            "confirm_password": accepted_password,
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert db.session.query(User).count() == 1


def test_api_registration_uses_configured_password_minimum(app, client):
    app.config["PASSWORD_MIN_LENGTH"] = 12
    verify_registration_email(client, "minimum-api@example.com")

    too_short = client.post(
        "/auth/register",
        json={
            "username": "minapi01",
            "email": "minimum-api@example.com",
            "full_name": "Minimum Api",
            "phone_number": "91234567",
            "password": "Abcdef12345",
            "confirm_password": "Abcdef12345",
        },
    )

    assert too_short.status_code == 400
    assert too_short.get_json() == {"error": "Invalid request"}
    assert db.session.query(User).count() == 0

    accepted_password = "Abcdef123456"
    response = client.post(
        "/auth/register",
        json={
            "username": "minapi01",
            "email": "minimum-api@example.com",
            "full_name": "Minimum Api",
            "phone_number": "91234567",
            "password": accepted_password,
            "confirm_password": accepted_password,
        },
    )

    assert response.status_code == 201
    assert db.session.query(User).count() == 1


def test_password_at_configured_max_length_can_register_and_login(client):
    password = "A" * PASSWORD_MAX_CHARS

    response = register(client, password=password)
    login_response = login(client, password=password)

    assert response.status_code == 302
    assert login_response.status_code == 302
    assert db.session.query(User).count() == 1

def test_oversized_registration_password_rejected_before_policy_processing(client, monkeypatch):
    def fail_policy(_password):
        pytest.fail("oversized password reached password policy processing")

    monkeypatch.setattr("app.auth.services.validate_password_policy", fail_policy)

    response = register(client, password="A" * 300)

    assert response.status_code == 400
    assert response.status_code != 500
    assert b"longer than 256 characters" in response.data
    assert db.session.query(User).count() == 0

def test_oversized_api_registration_password_rejected_cleanly(client, monkeypatch):
    def fail_policy(_password):
        pytest.fail("oversized password reached password policy processing")

    monkeypatch.setattr("app.auth.services.validate_password_policy", fail_policy)
    password = "A" * 300

    response = client.post(
        "/auth/register",
        json={
            "username": "oversized01",
            "email": "oversized@example.com",
            "full_name": "Oversized Test",
            "phone_number": "91234567",
            "password": password,
            "confirm_password": password,
        },
    )

    assert response.status_code == 400
    assert response.status_code != 500
    assert response.get_json() == {"error": "Invalid request"}
    assert db.session.query(User).count() == 0

def test_oversized_login_password_uses_generic_failure_without_hashing(app, client, monkeypatch):
    from app.auth.services import AuthError, authenticate_primary

    register(client)

    def fail_verify(_password, _password_hash):
        pytest.fail("oversized login password reached password hash verification")

    monkeypatch.setattr("app.auth.services.verify_password", fail_verify)

    with app.test_request_context(
        "/auth/login",
        method="POST",
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    ):
        with pytest.raises(AuthError) as exc_info:
            authenticate_primary("alice01", "A" * 300)

    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    assert exc_info.value.message == "Invalid username or password"
    assert exc_info.value.status_code == 401
    assert user.is_frozen is False
    assert user.security_locked_at is None

def test_oversized_web_login_password_fails_generically(client):
    register(client)

    response = login(client, password="A" * 300)

    assert response.status_code == 401
    assert response.status_code != 500
    assert b"Invalid username or password" in response.data
    assert b"longer than 256 characters" not in response.data

def test_oversized_api_login_password_fails_generically(client):
    register(client)

    response = client.post(
        "/auth/login",
        json={"identifier": "alice01", "password": "A" * 300},
    )

    assert response.status_code == 401
    assert response.status_code != 500
    assert response.get_json() == {"error": "Invalid username or password"}

def test_registration_requires_matching_confirm_password(client):
    verify_registration_email(client)
    response = client.post(
        "/register",
        data={
            "username": "alice01",
            "email": "alice@example.com",
            "full_name": "Alice Test",
            "phone_number": "91234567",
            "password": "correct horse battery staple",
            "confirm_password": "different horse battery staple",
        },
    )

    assert response.status_code == 400
    assert db.session.query(User).count() == 0

def test_registration_requires_full_name_and_valid_phone_number(client):
    verify_registration_email(client)
    missing_name = client.post(
        "/register",
        data={
            "username": "alice01",
            "email": "alice@example.com",
            "phone_number": "91234567",
            "password": "correct horse battery staple",
            "confirm_password": "correct horse battery staple",
        },
    )
    invalid_phone = client.post(
        "/register",
        data={
            "username": "alice01",
            "email": "alice@example.com",
            "full_name": "Alice Test",
            "phone_number": "71234567",
            "password": "correct horse battery staple",
            "confirm_password": "correct horse battery staple",
        },
    )

    assert missing_name.status_code == 400
    assert invalid_phone.status_code == 400
    assert b"Enter a valid Singapore phone number" in invalid_phone.data
    assert db.session.query(User).count() == 0


def test_registration_rejects_unsafe_full_name(client):
    verify_registration_email(client)

    response = client.post(
        "/register",
        data={
            "username": "alice01",
            "full_name": "<script>alert(1)</script>",
            "phone_number": "91234567",
            "password": "correct horse battery staple",
            "confirm_password": "correct horse battery staple",
        },
    )

    assert response.status_code == 400
    assert b"Full name must contain only English letters" in response.data
    assert db.session.query(User).count() == 0


def test_registration_rejects_duplicate_phone_with_generic_error(client):
    created = register(client)
    duplicate_phone = register(
        client,
        username="bob02",
        email="bob@example.com",
        full_name="Bob Test",
        phone_number="91234567",
    )

    assert created.status_code == 302
    assert duplicate_phone.status_code == 400
    assert b"Registration could not be completed with those details" in duplicate_phone.data
    assert db.session.query(User).count() == 1


def test_registration_prevents_canonical_email_alias_duplicates(client):
    created = register(
        client,
        email="first.last+signup@gmail.com",
    )
    with client.session_transaction() as sess:
        sess[REGISTRATION_OTP_VERIFIED_EMAIL_KEY] = "firstlast@gmail.com"
        sess[REGISTRATION_OTP_VERIFIED_AT_KEY] = int(time.time())
    duplicate = client.post(
        "/register",
        data={
            "username": "alias02",
            "email": "firstlast@gmail.com",
            "full_name": "Alias User",
            "phone_number": "91234568",
            "password": "correct horse battery staple",
            "confirm_password": "correct horse battery staple",
        },
    )
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()

    assert created.status_code == 302
    assert duplicate.status_code == 400
    assert b"Registration could not be completed with those details" in duplicate.data
    assert user.email == "first.last+signup@gmail.com"
    assert user.registration_email_canonical == "firstlast@gmail.com"


def test_registration_rejects_configured_temporary_email_domain(client):
    response = client.post(
        "/register/otp/request",
        data={"email": "customer@mailinator.com"},
    )

    assert response.status_code == 400
    assert b"Registration could not be started for that email" in response.data


def test_json_registration_returns_minimum_success_payload(client):
    verify_registration_email(client, "minimal@example.com")

    response = client.post(
        "/auth/register",
        json={
            "username": "minimal01",
            "email": "minimal@example.com",
            "full_name": "Minimal User",
            "phone_number": "91234567",
            "password": "correct horse battery staple",
            "confirm_password": "correct horse battery staple",
        },
    )

    assert response.status_code == 201
    assert response.get_json() == {
        "message": "Registration successful",
        "warnings": [],
    }

def test_api_registration_rejects_client_supplied_account_number(client):
    response = client.post(
        "/auth/register",
        json={
            "username": "alice01",
            "email": "alice@example.com",
            "full_name": "Alice Test",
            "phone_number": "91234567",
            "account_number": "999999999",
            "password": "correct horse battery staple",
            "confirm_password": "correct horse battery staple",
        },
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Invalid request"}
    assert db.session.query(User).count() == 0

def test_login_errors_are_generic_for_unknown_and_wrong_password(client):
    register(client)

    wrong_password = client.post(
        "/login",
        data={"identifier": "alice01", "password": "wrong-password"},
    )
    unknown_user = client.post(
        "/login",
        data={"identifier": "missing-user", "password": "wrong-password"},
    )

    assert wrong_password.status_code == 401
    assert unknown_user.status_code == 401
    assert b"Invalid username or password" in wrong_password.data
    assert b"Invalid username or password" in unknown_user.data

def test_failed_login_audit_includes_ip_timestamp_and_principal_ref(client, caplog):
    from app.security.audit import principal_reference

    register(client)
    caplog.set_level("INFO", logger=current_app.logger.name)

    response = client.post(
        "/auth/login",
        json={"identifier": "Alice@Example.com", "password": "wrong-password"},
        environ_overrides={"REMOTE_ADDR": "203.0.113.10"},
    )

    event = (
        db.session.query(SecurityAuditEvent)
        .filter_by(event_type="login", outcome="failure")
        .order_by(SecurityAuditEvent.id.desc())
        .one()
    )
    logs = "\n".join(record.getMessage() for record in caplog.records)
    payload = log_payloads(caplog, "security_audit_event")[-1]

    assert response.status_code == 401
    assert event.ip_address == "203.0.113.10"
    assert event.created_at is not None
    assert event.event_metadata["principal_ref"] == principal_reference("Alice@Example.com")
    assert len(event.event_metadata["principal_ref"]) == 32
    assert "Alice@Example.com" not in json.dumps(event.event_metadata)
    assert "Alice@Example.com" not in logs
    assert "wrong-password" not in logs
    assert payload["event_type"] == "login"
    assert payload["outcome"] == "failure"
    assert payload["ip_address"] == "203.0.113.10"
    assert payload["created_at"].endswith("Z")
    assert payload["logged_at"].endswith("Z")
    assert payload["metadata"]["principal_ref"] == event.event_metadata["principal_ref"]

def test_mfa_pending_api_response_does_not_leak_user_id(client):
    register(client)
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    enable_mfa_for_user()

    response = client.post(
        "/auth/login",
        json={"identifier": "alice01", "password": "correct horse battery staple"},
    )
    payload = response.get_json()

    assert response.status_code == 200
    assert payload == {"message": "MFA verification required", "mfa_required": True}
    assert "user_id" not in payload


def test_customer_api_mfa_counts_only_wrong_totp_and_clears_on_fresh_login(
    client,
    monkeypatch,
):
    from app.models import AuthAttemptCounter

    register(client)
    user, secret = enable_mfa_for_user()
    totp = pyotp.TOTP(secret, digits=6, interval=30)
    base_time = int(time.time())
    valid_code = totp.at(base_time)
    invalid_code = "000000" if valid_code != "000000" else "111111"

    primary = client.post(
        "/auth/login",
        json={"identifier": "alice01", "password": "correct horse battery staple"},
    )
    monkeypatch.setattr("app.auth.services.time.time", lambda: base_time)
    assert primary.status_code == 200
    for _attempt in range(5):
        response = client.post(
            "/auth/mfa/verify",
            json={"totp_code": invalid_code},
        )
        assert response.status_code == 401
        assert response.get_json() == {
            "error": "Incorrect code. Check your authenticator and try again."
        }

    valid_after_wrong_attempts = client.post(
        "/auth/mfa/verify",
        json={"totp_code": valid_code},
    )
    assert valid_after_wrong_attempts.status_code == 200
    assert (
        db.session.query(AuthAttemptCounter)
        .filter_by(scope="customer_mfa_login")
        .count()
        == 0
    )

    client.post(
        "/auth/login",
        json={"identifier": "alice01", "password": "correct horse battery staple"},
    )
    base_time += 30
    monkeypatch.setattr("app.auth.services.time.time", lambda: base_time)
    valid_code = totp.at(base_time)
    invalid_code = "000000" if valid_code != "000000" else "111111"
    for _attempt in range(5):
        assert (
            client.post("/auth/mfa/verify", json={"totp_code": invalid_code}).status_code
            == 401
        )
    blocked = client.post("/auth/mfa/verify", json={"totp_code": invalid_code})
    assert blocked.status_code == 429
    assert blocked.headers["Retry-After"].isdigit()
    assert "totp_code" not in blocked.get_data(as_text=True)

    client.post(
        "/auth/login",
        json={"identifier": "alice01", "password": "correct horse battery staple"},
    )
    base_time += 30
    monkeypatch.setattr("app.auth.services.time.time", lambda: base_time)
    recovered = client.post(
        "/auth/mfa/verify",
        json={"totp_code": totp.at(base_time)},
    )
    db.session.refresh(user)

    assert recovered.status_code == 200
    assert user.is_frozen is False


def test_customer_browser_mfa_valid_totp_survives_wrong_attempts_below_threshold(
    client,
    monkeypatch,
):
    register(client)
    _user, secret = enable_mfa_for_user()
    totp = pyotp.TOTP(secret, digits=6, interval=30)
    base_time = int(time.time())
    valid_code = totp.at(base_time)
    invalid_code = "000000" if valid_code != "000000" else "111111"

    primary = login(client)
    monkeypatch.setattr("app.auth.services.time.time", lambda: base_time)
    assert primary.status_code == 302
    for _attempt in range(5):
        response = client.post("/mfa/verify", data={"totp_code": invalid_code})
        assert response.status_code == 401
        markup = response.get_data(as_text=True)
        assert "Incorrect code. Check your authenticator and try again." in markup
        assert "Too many requests" not in markup

    valid_after_wrong_attempts = client.post(
        "/mfa/verify",
        data={"totp_code": valid_code},
    )

    assert valid_after_wrong_attempts.status_code == 302
    assert valid_after_wrong_attempts.headers["Location"].endswith("/dashboard")


def test_login_backoff_starts_after_three_failures(client):
    register(client)

    failures = [
        client.post(
            "/auth/login",
            json={"identifier": "alice01", "password": "wrong-password"},
        )
        for _attempt in range(3)
    ]
    blocked = client.post("/auth/login", json={"identifier": "alice01", "password": "wrong-password"})

    assert [response.status_code for response in failures] == [401, 401, 401]
    assert blocked.status_code == 429
    assert blocked.get_json()["error"] == "Too many failed attempts. Please wait before trying again."
    assert blocked.headers["X-Auth-Retry-After"] == "1"

def test_login_rate_limits_include_per_minute_and_daily_limits(client):
    auth_routes = Path("app/auth/routes.py").read_text(encoding="utf-8")
    web_routes = Path("app/web/routes.py").read_text(encoding="utf-8")

    for route_source in (auth_routes, web_routes):
        assert '@limiter.limit("50 per day", key_func=get_remote_address)' in route_source
        assert '@limiter.limit("50 per day", key_func=request_principal)' in route_source
        assert '@limiter.limit("5 per minute", key_func=get_remote_address)' in route_source
        assert '@limiter.limit("5 per minute", key_func=request_principal)' in route_source

    for attempt in range(5):
        response = client.post(
            "/auth/login",
            json={"identifier": f"missing{attempt}", "password": "wrong-password"},
        )
        assert response.status_code == 401

    limited = client.post(
        "/auth/login",
        json={"identifier": "missing-final", "password": "wrong-password"},
    )

    assert limited.status_code == 429

def test_account_lockout_cannot_be_bypassed_from_a_different_source_ip(client):
    register(client)

    attacker_ip = "198.51.100.10"
    victim_ip = "198.51.100.20"
    for _attempt in range(5):
        api_login_from_ip(client, attacker_ip, password="wrong-password")

    response = api_login_from_ip(client, victim_ip)
    payload = response.get_json()

    assert response.status_code == 401
    assert payload == {"error": "Invalid username or password"}

def test_request_principal_is_hashed_and_ip_scoped(app):
    from app.security.rate_limits import request_principal

    with app.test_request_context(
        "/auth/login",
        method="POST",
        json={"identifier": "Victim@Example.COM", "password": "wrong-password"},
        environ_overrides={"REMOTE_ADDR": "198.51.100.10"},
    ):
        first_key = request_principal()

    with app.test_request_context(
        "/auth/login",
        method="POST",
        json={"identifier": "victim@example.com", "password": "wrong-password"},
        environ_overrides={"REMOTE_ADDR": "198.51.100.20"},
    ):
        second_key = request_principal()

    assert first_key.startswith("principal:")
    assert second_key.startswith("principal:")
    assert first_key != second_key
    assert "victim" not in first_key.casefold()
    assert "example" not in first_key.casefold()
    assert "198.51.100.10" not in first_key

def test_repeated_password_failures_lock_known_customer_account(app, client):
    from app.auth.services import AuthError, authenticate_primary
    from app.security.rate_limits import clear_failures

    register(client)
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()

    for _attempt in range(3):
        with app.test_request_context(
            "/auth/login",
            method="POST",
            environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
        ):
            try:
                authenticate_primary("alice01", "wrong-password")
            except AuthError:
                pass

    db.session.refresh(user)

    assert user.is_frozen is True
    assert user.security_locked_at is not None
    assert user.security_lock_reason == "password_failed_attempts"
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="account_lock", outcome="locked").count() == 1

    clear_failures("login", "127.0.0.1:alice01")
    response = login(client)
    db.session.refresh(user)

    assert response.status_code == 401
    assert user.failed_login_count == 3

def test_repeated_mfa_failures_freeze_account(app, client):
    from flask import session
    from app.auth.services import AuthError, authenticate_primary, complete_pending_mfa

    register(client)
    user, _secret = enable_mfa_for_user()

    for _window in range(2):
        for _attempt in range(5):
            with app.test_request_context(
                "/auth/mfa/verify",
                method="POST",
                environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
            ):
                session["pending_mfa_user_id"] = user.id
                try:
                    complete_pending_mfa("000000")
                except AuthError:
                    pass
        if _window == 0:
            with app.test_request_context(
                "/auth/login",
                method="POST",
                environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
            ):
                authenticate_primary("alice01", "correct horse battery staple")

    db.session.refresh(user)

    assert user.is_frozen is True
    assert user.security_locked_at is not None
    assert user.security_lock_reason == "mfa_failed_attempts"

def test_api_validation_errors_do_not_expose_schema_details(client):
    response = client.post("/auth/login", json={})
    payload = response.get_json()

    assert response.status_code == 400
    assert payload == {"error": "Invalid request"}

def test_dummy_password_hash_tracks_current_pbkdf2_configuration(app):
    from app.auth.services import _dummy_password_hash

    original_iterations = app.config["PASSWORD_PBKDF2_ITERATIONS"]
    original_hash = _dummy_password_hash()

    try:
        app.config["PASSWORD_PBKDF2_ITERATIONS"] = original_iterations + 1
        updated_hash = _dummy_password_hash()
    finally:
        app.config["PASSWORD_PBKDF2_ITERATIONS"] = original_iterations
        app.config.pop("_DUMMY_PASSWORD_HASH", None)
        app.config.pop("_DUMMY_PASSWORD_HASH_CONFIG", None)

    assert updated_hash != original_hash
    assert f"$i={original_iterations + 1}$" in updated_hash

def test_unknown_and_known_login_failures_use_same_backoff_path(client):
    register(client)
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()

    known_response = client.post(
        "/auth/login",
        json={"identifier": "alice01", "password": "wrong-password-value"},
    )
    unknown_response = client.post(
        "/auth/login",
        json={"identifier": "missing-user", "password": "wrong-password-value"},
    )
    db.session.refresh(user)

    assert known_response.status_code == 401
    assert unknown_response.status_code == 401
    assert known_response.get_json() == unknown_response.get_json()
    assert user.failed_login_count == 1

def test_hash_password_uses_configured_pbkdf2_iterations(app):
    with app.app_context():
        password_hash = hash_password("correct horse battery staple")

    assert password_hash.startswith(f"{PBKDF2_PREFIX}$v1$i=600000$")
