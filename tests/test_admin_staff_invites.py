from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone

import pyotp
import pytest
from sqlalchemy import func

from app.extensions import db
from app.models import PersonIdentityLink, SecurityAuditEvent, StaffInvite, User
from app.security.crypto import encrypt_mfa_secret
from app.security.email import password_reset_outbox
from app.security.passwords import hash_password


ROOT_EMAIL = "root1@sit.singaporetech.edu.sg"
ROOT_PASSWORD = "correct horse battery staple"
STAFF_PASSWORD = "another correct horse battery staple"
_FIXED_TOTP_TIME = int(time.time())


@pytest.fixture(autouse=True)
def freeze_totp_verifier_time(monkeypatch):
    global _FIXED_TOTP_TIME
    _FIXED_TOTP_TIME = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: _FIXED_TOTP_TIME)


def _create_staff_identity(
    *,
    username: str,
    email: str,
    account_type: str,
    phone_number: str,
    password: str = ROOT_PASSWORD,
    active: bool = True,
    personal_email: str | None = None,
) -> tuple[User, str]:
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        account_type=account_type,
        account_status="active" if active else "setup_pending",
        full_name=username.replace("-", " ").title(),
        phone_number=phone_number,
        account_number=None,
        staff_personal_email=personal_email,
        workplace_email_verified_at=datetime.now(timezone.utc) if active else None,
    )
    db.session.add(user)
    db.session.flush()
    secret = pyotp.random_base32(length=32)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(secret, user.id)
    user.mfa_enabled = active
    db.session.commit()
    return user, secret


def _login_admin(client, secret: str, email: str = ROOT_EMAIL, password: str = ROOT_PASSWORD):
    password_response = client.post(
        "/login",
        json={"workplace_email": email, "password": password},
    )
    assert password_response.status_code == 200
    verify_response = client.post(
        "/mfa/verify",
        json={"totp_code": _stable_totp(secret)},
    )
    assert verify_response.status_code == 200
    return verify_response


def _stable_totp(secret: str) -> str:
    return pyotp.TOTP(secret, digits=6, interval=30).at(_FIXED_TOTP_TIME)


def _root_with_setup_pending_target(
    admin_client,
    *,
    username: str,
    email: str,
    phone_number: str,
    role: str = "staff",
) -> tuple[User, str, User]:
    root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    target, _target_secret = _create_staff_identity(
        username=username,
        email=email,
        account_type=role,
        phone_number=phone_number,
        active=False,
    )
    _login_admin(admin_client, secret)
    return root, secret, target


def _create_invite(client, secret: str, **overrides):
    payload = {
        "workplace_email": "staff.person@sit.singaporetech.edu.sg",
        "role": "staff",
        "totp_code": _stable_totp(secret),
    }
    payload.update(overrides)
    return client.post("/invites", json=payload)


def _latest_invite_token() -> str:
    body = password_reset_outbox()[-1]["body"]
    match = re.search(r"/invites/accept/([A-Za-z0-9_-]{32,256})", body)
    assert match, body
    return match.group(1)


def _latest_workplace_code() -> str:
    body = password_reset_outbox()[-1]["body"]
    match = re.search(r"\b([0-9]{6})\b", body)
    assert match, body
    return match.group(1)


def _staff_invite_start_payload(**overrides):
    payload = {
        "full_name": "Staff Person",
        "phone_number": "91234568",
        "password": STAFF_PASSWORD,
        "confirm_password": STAFF_PASSWORD,
    }
    payload.update(overrides)
    return payload


def _assert_invite_acceptance_security_headers(response):
    cache_control = response.headers.get("Cache-Control", "")
    assert "no-store" in cache_control
    assert "private" in cache_control
    assert response.headers.get("Pragma") == "no-cache"
    assert response.headers.get("Referrer-Policy") == "origin"


def _assert_generic_invite_unavailable_page(response, token: str):
    body = response.get_data(as_text=True)
    assert response.status_code == 401
    assert response.mimetype == "text/html"
    assert "Staff invite unavailable" in body
    assert "This invite link is invalid or expired" in body
    assert "Security token expired or invalid" not in body
    assert "Private admin request status" not in body
    assert token not in body
    for forbidden in (
        "staff.person@sit.singaporetech.edu.sg",
        "workplace_email",
        "acceptance_",
        "setup_user",
        "revoked_by_user_id",
        "used_by_user_id",
    ):
        assert forbidden not in body
    _assert_invite_acceptance_security_headers(response)


def _invite_info_json(client, token: str):
    return client.get(
        f"/invites/accept/{token}",
        headers={"Accept": "application/json"},
    )


def _csrf_token_from(response) -> str:
    match = re.search(
        r'name="csrf_token"[^>]*value="([^"]+)"',
        response.get_data(as_text=True),
    )
    assert match is not None
    return match.group(1)


def _insert_invite_for_token(token: str, creator: User, **overrides) -> StaffInvite:
    from app.admin.services import invite_token_hash

    defaults = {
        "token_hash": invite_token_hash(token),
        "workplace_email_normalized": "staff.person@sit.singaporetech.edu.sg",
        "role": "staff",
        "status": "pending",
        "created_by_user_id": creator.id,
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
    }
    defaults.update(overrides)
    invite = StaffInvite(**defaults)
    db.session.add(invite)
    db.session.commit()
    return invite


def test_root_admin_can_create_hashed_staff_invite(admin_client):
    _root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret)

    response = _create_invite(admin_client, secret)
    token = _latest_invite_token()
    invite = db.session.execute(db.select(StaffInvite)).scalar_one()
    events = db.session.query(SecurityAuditEvent).filter_by(event_type="staff_invite_created").all()
    email_event = db.session.query(SecurityAuditEvent).filter_by(event_type="staff_invite_email").one()

    assert response.status_code == 201
    assert response.get_json()["invite"]["workplace_email"] == "staff.person@sit.singaporetech.edu.sg"
    assert "personal_email_ref" not in response.get_json()["invite"]
    assert invite.token_hash != token
    assert token not in json.dumps(invite.__dict__, default=str)
    assert invite.expires_at.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc)
    assert password_reset_outbox()[-1]["to"] == "staff.person@sit.singaporetech.edu.sg"
    assert "temporary password" not in password_reset_outbox()[-1]["body"].casefold()
    assert events and "token" not in json.dumps(events[0].event_metadata).casefold()
    assert "personal_email_ref" not in events[0].event_metadata
    assert email_event.outcome == "queued"
    assert email_event.event_metadata["status"] == "pending"
    assert invite.delivery_status == "queued"
    assert response.get_json()["invite"]["delivery_status"] == "queued"
    assert token not in json.dumps(email_event.event_metadata, default=str)


def test_only_root_admin_with_totp_stepup_can_create_invites(admin_client):
    _staff, staff_secret = _create_staff_identity(
        username="staff-admin",
        email="staff.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, staff_secret, email="staff.admin@sit.singaporetech.edu.sg")

    non_root = _create_invite(admin_client, staff_secret)
    assert non_root.status_code == 403

    admin_client.post("/logout")
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234568",
    )
    _login_admin(admin_client, root_secret)
    missing_stepup = admin_client.post(
        "/invites",
        json={
            "workplace_email": "person@sit.singaporetech.edu.sg",
            "role": "staff",
        },
    )

    assert missing_stepup.status_code == 400
    assert db.session.query(StaffInvite).count() == 0


def test_invite_creation_validates_server_side_email_and_role_policy(admin_client):
    _root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret)

    cases = [
        {"workplace_email": "staff@sit.singaporetech.edu.sg.evil.com"},
        {"workplace_email": "staff@gmail.com"},
        {"personal_email": "staff.person@gmail.com"},
        {"role": "root_admin"},
    ]
    responses = [_create_invite(admin_client, secret, **case) for case in cases]

    assert [response.status_code for response in responses] == [400, 400, 400, 400]
    assert db.session.query(StaffInvite).count() == 0


def test_invite_creation_rejects_root_admin_allowlisted_target_without_user_row(admin_client):
    _root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret)

    response = _create_invite(
        admin_client,
        secret,
        workplace_email="root2@sit.singaporetech.edu.sg",
        role="admin",
    )
    event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="staff_invite_create",
        outcome="blocked",
    ).one()

    assert response.status_code == 400
    assert db.session.query(StaffInvite).count() == 0
    assert event.event_metadata["reason"] == "root_admin_allowlist_target"
    assert "root2@sit.singaporetech.edu.sg" not in json.dumps(event.event_metadata)


def test_invite_creation_rejects_reused_and_previous_step_totp_with_safe_guidance(
    admin_client,
):
    _root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret)
    reused_code = _stable_totp(secret)

    first = _create_invite(
        admin_client,
        secret,
        workplace_email="staff.one@sit.singaporetech.edu.sg",
        totp_code=reused_code,
    )
    replayed = _create_invite(
        admin_client,
        secret,
        workplace_email="staff.two@sit.singaporetech.edu.sg",
        totp_code=reused_code,
    )

    with admin_client.session_transaction() as session_data:
        session_data.clear()
    _second_root, second_secret = _create_staff_identity(
        username="second-root-admin",
        email="root2@sit.singaporetech.edu.sg",
        account_type="root_admin",
        phone_number="91234569",
    )
    _login_admin(admin_client, second_secret, email="root2@sit.singaporetech.edu.sg")
    previous_step_code = pyotp.TOTP(second_secret, digits=6, interval=30).at(_FIXED_TOTP_TIME - 30)
    previous = _create_invite(
        admin_client,
        second_secret,
        workplace_email="staff.three@sit.singaporetech.edu.sg",
        totp_code=previous_step_code,
    )

    assert first.status_code == 201
    assert replayed.status_code == 403
    assert previous.status_code == 403
    assert db.session.query(StaffInvite).count() == 1
    for response in (replayed, previous):
        body = response.get_json()["error"]
        assert "Fresh MFA verification is required" in body
        assert "Wait for a new authenticator code" in body
        assert reused_code not in body
        assert previous_step_code not in body


def test_invite_email_failure_revokes_pending_invite_for_recovery(
    admin_client,
    monkeypatch,
):
    _root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret)
    monkeypatch.setattr(
        "app.admin.services.send_security_email",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("smtp down")),
    )

    response = _create_invite(admin_client, secret)
    invite = db.session.execute(db.select(StaffInvite)).scalar_one()
    email_event = db.session.query(SecurityAuditEvent).filter_by(event_type="staff_invite_email").one()

    assert response.status_code == 503
    assert invite.status == "revoked"
    assert invite.delivery_status == "failed"
    assert invite.revoked_at is not None
    assert email_event.outcome == "failure"
    assert email_event.event_metadata["reason"] == "email_delivery_failed"
    assert invite.status not in {"pending", "totp_pending"}
    page = admin_client.get("/invites")
    assert "Backend handoff failed" in page.get_data(as_text=True)


def test_invite_creation_accepts_configured_admin_email_domains(admin_client):
    _root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret)

    response = _create_invite(
        admin_client,
        secret,
        workplace_email="staff.second-domain@singaporetech.edu.sg",
    )

    assert response.status_code == 201
    assert response.get_json()["invite"]["workplace_email"] == "staff.second-domain@singaporetech.edu.sg"


def test_staff_invite_revoke_redirects_html_clients(admin_client):
    _root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret)
    assert _create_invite(admin_client, secret).status_code == 201
    invite = db.session.execute(db.select(StaffInvite)).scalar_one()

    response = admin_client.post(
        f"/invites/{invite.id}/revoke",
        data={"totp_code": _stable_totp(secret)},
    )

    assert response.status_code == 303
    assert response.headers["Location"].endswith("/invites")
    db.session.refresh(invite)
    assert invite.status == "revoked"
    assert invite.revoked_at is not None


def test_invites_page_renders_actions_and_delivery_guidance(admin_client):
    _root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret)
    assert _create_invite(admin_client, secret).status_code == 201

    response = admin_client.get("/invites")
    body = response.get_data(as_text=True)
    invite = db.session.execute(db.select(StaffInvite)).scalar_one()
    invite.delivery_status = "unconfirmed"
    db.session.commit()
    unconfirmed_body = admin_client.get("/invites").get_data(as_text=True)

    assert response.status_code == 200
    assert "Queued to backend" in body
    assert "Recipient mailbox delivery remains unconfirmed." in body
    assert "Delivery unconfirmed" in unconfirmed_body
    assert "No backend handoff evidence is available." in unconfirmed_body
    assert "Revoke invite" in body
    assert "Reissue invite" in body
    assert "currently signed-in root admin" in body
    assert "Wait for the next code if this one is close to expiry" in body
    assert body.index("Revoke invite") < body.index('id="revoke-totp-')
    assert body.index("Reissue invite") < body.index('id="reissue-totp-')


def test_staff_invite_revoke_uses_rendered_csrf_and_fresh_totp(
    admin_app,
    admin_client,
    monkeypatch,
):
    _root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret)
    assert _create_invite(admin_client, secret).status_code == 201
    invite = db.session.execute(db.select(StaffInvite)).scalar_one()
    original_csrf = admin_app.config["WTF_CSRF_ENABLED"]
    admin_app.config["WTF_CSRF_ENABLED"] = True
    try:
        page = admin_client.get("/invites")
        match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page.get_data(as_text=True))
        assert match is not None
        fresh_time = _FIXED_TOTP_TIME + 31
        monkeypatch.setattr("app.auth.services.time.time", lambda: fresh_time)
        response = admin_client.post(
            f"/invites/{invite.id}/revoke",
            data={
                "csrf_token": match.group(1),
                "totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(fresh_time),
            },
            follow_redirects=False,
        )
    finally:
        admin_app.config["WTF_CSRF_ENABLED"] = original_csrf

    assert page.status_code == 200
    assert response.status_code == 303
    db.session.refresh(invite)
    assert invite.status == "revoked"


def test_root_admin_can_reissue_pending_invite_with_new_token(admin_client, monkeypatch):
    _root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret)
    assert _create_invite(admin_client, secret).status_code == 201
    original_token = _latest_invite_token()
    invite = db.session.execute(db.select(StaffInvite)).scalar_one()
    invite.acceptance_started_at = datetime.now(timezone.utc)
    invite.acceptance_start_count = 2
    db.session.commit()
    fresh_time = _FIXED_TOTP_TIME + 31
    monkeypatch.setattr("app.auth.services.time.time", lambda: fresh_time)

    response = admin_client.post(
        f"/invites/{invite.id}/reissue",
        json={"totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(fresh_time)},
    )
    new_token = _latest_invite_token()
    old_lookup = _invite_info_json(admin_client, original_token)
    new_lookup = _invite_info_json(admin_client, new_token)
    new_browser = admin_client.get(f"/invites/accept/{new_token}")
    db.session.refresh(invite)
    reissue_event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="staff_invite_reissued",
        outcome="success",
    ).one()

    assert response.status_code == 200
    assert new_token != original_token
    assert old_lookup.status_code == 401
    assert new_lookup.status_code == 200
    assert new_browser.mimetype == "text/html"
    assert "Set up your staff access" in new_browser.get_data(as_text=True)
    assert invite.status == "pending"
    assert invite.delivery_status == "queued"
    assert invite.acceptance_start_count == 0
    assert invite.acceptance_started_at is None
    assert original_token not in json.dumps(reissue_event.event_metadata, default=str)


def test_root_admin_reissue_mfa_step_up_outcomes_are_safe(
    admin_app,
    admin_client,
    monkeypatch,
):
    _root_one, root_one_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _root_two, root_two_secret = _create_staff_identity(
        username="second-root-admin",
        email="root2@sit.singaporetech.edu.sg",
        account_type="root_admin",
        phone_number="91234569",
    )
    _root_three, root_three_secret = _create_staff_identity(
        username="third-root-admin",
        email="root3@sit.singaporetech.edu.sg",
        account_type="root_admin",
        phone_number="91234570",
    )
    root_two_client = admin_app.test_client()
    root_three_client = admin_app.test_client()
    _login_admin(admin_client, root_one_secret)
    _login_admin(root_two_client, root_two_secret, email="root2@sit.singaporetech.edu.sg")
    _login_admin(root_three_client, root_three_secret, email="root3@sit.singaporetech.edu.sg")
    assert _create_invite(admin_client, root_one_secret).status_code == 201
    invite = db.session.execute(db.select(StaffInvite)).scalar_one()
    original_token = _latest_invite_token()
    fresh_time = _FIXED_TOTP_TIME + 31
    monkeypatch.setattr("app.auth.services.time.time", lambda: fresh_time)
    valid_code = pyotp.TOTP(root_one_secret, digits=6, interval=30).at(fresh_time)

    valid = admin_client.post(f"/invites/{invite.id}/reissue", json={"totp_code": valid_code})
    new_token = _latest_invite_token()
    replayed = admin_client.post(f"/invites/{invite.id}/reissue", json={"totp_code": valid_code})
    adjacent_code = pyotp.TOTP(root_two_secret, digits=6, interval=30).at(fresh_time - 30)
    adjacent = root_two_client.post(f"/invites/{invite.id}/reissue", json={"totp_code": adjacent_code})
    malformed = root_two_client.post(f"/invites/{invite.id}/reissue", json={"totp_code": "not-a-code"})
    wrong_account_code = valid_code
    wrong_account = root_three_client.post(
        f"/invites/{invite.id}/reissue",
        json={"totp_code": wrong_account_code},
    )
    backed_off = root_three_client.post(
        f"/invites/{invite.id}/reissue",
        json={"totp_code": wrong_account_code},
    )
    db.session.refresh(invite)

    assert valid.status_code == 200
    assert new_token != original_token
    assert replayed.status_code == 403
    assert adjacent.status_code == 403
    assert malformed.status_code == 400
    assert wrong_account.status_code == 403
    assert backed_off.status_code == 429
    assert backed_off.headers["Retry-After"].isdigit()
    assert backed_off.headers["X-Auth-Retry-After"].isdigit()
    assert invite.status == "pending"
    assert _invite_info_json(admin_client, original_token).status_code == 401
    assert _invite_info_json(admin_client, new_token).status_code == 200
    for response, submitted_code in (
        (replayed, valid_code),
        (adjacent, adjacent_code),
        (malformed, "not-a-code"),
        (wrong_account, wrong_account_code),
        (backed_off, wrong_account_code),
    ):
        body = response.get_data(as_text=True)
        assert submitted_code not in body
        assert "Fresh MFA verification is required" in body or response.status_code in {400, 429}


def test_reissue_delivery_failure_is_persisted_without_rotating_the_live_token(
    admin_client,
    monkeypatch,
):
    _root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret)
    assert _create_invite(admin_client, secret).status_code == 201
    original_token = _latest_invite_token()
    invite = db.session.execute(db.select(StaffInvite)).scalar_one()
    original_token_hash = invite.token_hash
    fresh_time = _FIXED_TOTP_TIME + 31
    monkeypatch.setattr("app.auth.services.time.time", lambda: fresh_time)
    monkeypatch.setattr(
        "app.admin.services.send_security_email",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("smtp down")),
    )

    response = admin_client.post(
        f"/invites/{invite.id}/reissue",
        json={"totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(fresh_time)},
    )
    db.session.refresh(invite)

    assert response.status_code == 503
    assert invite.status == "pending"
    assert invite.token_hash == original_token_hash
    assert invite.delivery_status == "failed"
    assert _invite_info_json(admin_client, original_token).status_code == 200
    assert "Backend handoff failed" in admin_client.get("/invites").get_data(as_text=True)


def test_root_admin_can_resend_setup_invite_for_stuck_setup_pending_account(admin_client):
    _root, secret, target = _root_with_setup_pending_target(
        admin_client,
        username="stuck-staff",
        email="stuck.staff@sit.singaporetech.edu.sg",
        phone_number="91234568",
    )
    stale_invite = StaffInvite(
        token_hash="0" * 64,
        workplace_email_normalized="stuck.staff@sit.singaporetech.edu.sg",
        role="staff",
        status="revoked",
        delivery_status="unconfirmed",
        created_by_user_id=_root.id,
        created_at=datetime.now(timezone.utc) - timedelta(days=2),
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        revoked_at=datetime.now(timezone.utc) - timedelta(days=1),
        revoked_by_user_id=_root.id,
    )
    db.session.add(stale_invite)
    db.session.commit()

    still_blocked = _create_invite(
        admin_client,
        secret,
        workplace_email="stuck.staff@sit.singaporetech.edu.sg",
    )

    response = admin_client.post(
        f"/staff/{target.id}/resend-setup",
        json={"totp_code": _stable_totp(secret)},
    )
    body = response.get_json()
    new_token = _latest_invite_token()
    new_invite = (
        db.session.query(StaffInvite)
        .filter_by(workplace_email_normalized="stuck.staff@sit.singaporetech.edu.sg")
        .filter(StaffInvite.id != stale_invite.id)
        .one()
    )
    resend_event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="staff_invite_resent",
        outcome="success",
    ).one()
    identity_count = (
        db.session.query(User)
        .filter(func.lower(User.email) == "stuck.staff@sit.singaporetech.edu.sg")
        .count()
    )

    assert still_blocked.status_code == 400
    assert response.status_code == 201
    assert new_invite.setup_user_id == target.id
    assert new_invite.status == "pending"
    assert new_invite.delivery_status == "queued"
    assert new_invite.token_hash != stale_invite.token_hash
    assert identity_count == 1
    assert _invite_info_json(admin_client, new_token).status_code == 200
    assert new_token not in json.dumps(body, default=str)
    assert new_token not in json.dumps(resend_event.event_metadata, default=str)
    assert "stuck.staff@sit.singaporetech.edu.sg" not in json.dumps(resend_event.event_metadata, default=str)


def test_reset_setup_alone_does_not_resend_email_and_resend_requires_explicit_action(
    admin_client,
    monkeypatch,
):
    _root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    target, _target_secret = _create_staff_identity(
        username="target-staff",
        email="target.staff@sit.singaporetech.edu.sg",
        account_type="staff",
        phone_number="91234568",
        active=True,
    )
    _login_admin(admin_client, secret)
    outbox_before = len(password_reset_outbox())
    invites_before = db.session.query(StaffInvite).count()

    reset = admin_client.post(
        f"/staff/{target.id}/reset-activation",
        json={"totp_code": _stable_totp(secret)},
    )
    db.session.refresh(target)

    # Reset activation routes through maker-checker: it queues an approval
    # request without sending a setup email or minting a new invite, and the
    # target keeps its current state until a second root admin approves.
    assert reset.status_code == 200
    assert target.account_status == "active"
    assert len(password_reset_outbox()) == outbox_before
    assert db.session.query(StaffInvite).count() == invites_before

    # A completed reset leaves the account stuck in setup_pending. The explicit
    # resend action is what actually mints and delivers a fresh setup link.
    target.account_status = "setup_pending"
    target.mfa_enabled = False
    db.session.commit()

    fresh_time = _FIXED_TOTP_TIME + 31
    monkeypatch.setattr("app.auth.services.time.time", lambda: fresh_time)
    resend = admin_client.post(
        f"/staff/{target.id}/resend-setup",
        json={"totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(fresh_time)},
    )

    assert resend.status_code == 201
    assert len(password_reset_outbox()) == outbox_before + 1
    assert db.session.query(StaffInvite).count() == invites_before + 1


def test_resend_setup_invite_rejects_non_root_admin_self_and_ineligible_targets(admin_app, admin_client):
    root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    plain_admin, admin_secret = _create_staff_identity(
        username="plain-admin",
        email="plain.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234568",
    )
    active_target, _active_secret = _create_staff_identity(
        username="active-staff",
        email="active.staff@sit.singaporetech.edu.sg",
        account_type="staff",
        phone_number="91234569",
        active=True,
    )
    stuck_target, _stuck_secret = _create_staff_identity(
        username="stuck-staff-2",
        email="stuck.staff.two@sit.singaporetech.edu.sg",
        account_type="staff",
        phone_number="91234570",
        active=False,
    )
    admin_client_2 = admin_app.test_client()
    _login_admin(admin_client_2, admin_secret, email="plain.admin@sit.singaporetech.edu.sg")
    _login_admin(admin_client, root_secret)

    non_root = admin_client_2.post(
        f"/staff/{stuck_target.id}/resend-setup",
        json={"totp_code": _stable_totp(admin_secret)},
    )
    self_action = admin_client.post(
        f"/staff/{root.id}/resend-setup",
        json={"totp_code": _stable_totp(root_secret)},
    )
    ineligible = admin_client.post(
        f"/staff/{active_target.id}/resend-setup",
        json={"totp_code": _stable_totp(root_secret)},
    )
    missing_target = admin_client.post(
        "/staff/999999/resend-setup",
        json={"totp_code": _stable_totp(root_secret)},
    )

    assert non_root.status_code == 403
    assert self_action.status_code == 403
    assert ineligible.status_code == 404
    assert missing_target.status_code == 404
    assert db.session.query(StaffInvite).count() == 0


def test_resend_setup_invite_step_up_outcomes_are_safe(admin_client, monkeypatch):
    _root, secret, target = _root_with_setup_pending_target(
        admin_client,
        username="stuck-staff-3",
        email="stuck.staff.three@sit.singaporetech.edu.sg",
        phone_number="91234568",
    )
    fresh_time = _FIXED_TOTP_TIME + 31
    monkeypatch.setattr("app.auth.services.time.time", lambda: fresh_time)
    valid_code = pyotp.TOTP(secret, digits=6, interval=30).at(fresh_time)

    missing = admin_client.post(f"/staff/{target.id}/resend-setup", json={})
    malformed = admin_client.post(f"/staff/{target.id}/resend-setup", json={"totp_code": "not-a-code"})
    assert db.session.query(StaffInvite).count() == 0

    valid = admin_client.post(f"/staff/{target.id}/resend-setup", json={"totp_code": valid_code})
    replayed = admin_client.post(f"/staff/{target.id}/resend-setup", json={"totp_code": valid_code})
    replayed_body = replayed.get_data(as_text=True)

    assert missing.status_code == 400
    assert malformed.status_code == 400
    assert valid.status_code == 201
    assert replayed.status_code == 403
    assert "Fresh MFA verification is required" in replayed_body
    assert valid_code not in replayed_body
    assert db.session.query(StaffInvite).count() == 1


def test_resend_setup_invite_delivery_failure_revokes_invite_fail_closed(admin_client, monkeypatch):
    _root, secret, target = _root_with_setup_pending_target(
        admin_client,
        username="stuck-staff-4",
        email="stuck.staff.four@sit.singaporetech.edu.sg",
        phone_number="91234568",
    )
    monkeypatch.setattr(
        "app.admin.services.send_security_email",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("smtp down")),
    )

    response = admin_client.post(
        f"/staff/{target.id}/resend-setup",
        json={"totp_code": _stable_totp(secret)},
    )
    invite = db.session.execute(db.select(StaffInvite)).scalar_one()
    db.session.refresh(target)

    assert response.status_code == 503
    assert invite.status == "revoked"
    assert invite.delivery_status == "failed"
    assert invite.revoked_by_user_id == _root.id
    assert target.account_status == "setup_pending"


def test_resend_setup_invite_service_guard_rejects_non_root_actor(admin_app):
    with admin_app.app_context():
        from app.admin.services import AuthError, resend_staff_setup_invite

        actor, _actor_secret = _create_staff_identity(
            username="plain-admin-guard",
            email="plain.admin.guard@sit.singaporetech.edu.sg",
            account_type="admin",
            phone_number="91234567",
        )
        target, _target_secret = _create_staff_identity(
            username="stuck-staff-guard",
            email="stuck.staff.guard@sit.singaporetech.edu.sg",
            account_type="staff",
            phone_number="91234568",
            active=False,
        )

        with pytest.raises(AuthError) as excinfo:
            resend_staff_setup_invite(actor, target.id, "000000")

        assert excinfo.value.status_code == 403
        assert db.session.query(StaffInvite).count() == 0


def test_invite_acceptance_requires_turnstile_when_enabled(admin_app, admin_client, monkeypatch):
    admin_app.config["TURNSTILE_ENABLED"] = True
    admin_app.config["TURNSTILE_SECRET_KEY"] = "turnstile-secret"
    _root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret)
    assert _create_invite(admin_client, secret).status_code == 201
    token = _latest_invite_token()
    invite = db.session.execute(db.select(StaffInvite)).scalar_one()

    missing = admin_client.post(
        f"/invites/accept/{token}/start",
        json={
            "full_name": "Staff Person",
            "phone_number": "91234568",
            "password": STAFF_PASSWORD,
            "confirm_password": STAFF_PASSWORD,
        },
    )
    db.session.refresh(invite)
    missing_event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="staff_invite_accept",
        outcome="failure",
    ).one()

    assert missing.status_code == 400
    assert missing.get_json() == {"error": "Complete the security challenge before starting setup."}
    assert invite.status == "pending"
    assert invite.setup_user_id is None
    assert db.session.query(User).count() == 1
    assert missing_event.event_metadata == {"reason": "turnstile_failed"}
    assert "browser-token" not in json.dumps(missing_event.event_metadata, default=str)

    calls = []

    def fake_require(action, token_value=None):
        calls.append((action, token_value))

    monkeypatch.setattr("app.admin.services.require_turnstile", fake_require)
    valid = admin_client.post(
        f"/invites/accept/{token}/start",
        json={
            "full_name": "Staff Person",
            "phone_number": "91234568",
            "password": STAFF_PASSWORD,
            "confirm_password": STAFF_PASSWORD,
            "turnstile_token": "browser-token",
        },
    )

    assert valid.status_code == 200
    assert calls == [("admin_invite_accept", "browser-token")]


def test_invite_acceptance_rejects_stale_turnstile_and_accepts_standard_field(
    admin_app,
    admin_client,
    monkeypatch,
    caplog,
):
    from app.security.turnstile import TurnstileError

    admin_app.config["TURNSTILE_ENABLED"] = True
    admin_app.config["TURNSTILE_SECRET_KEY"] = "turnstile-secret"
    _root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret)
    assert _create_invite(admin_client, secret).status_code == 201
    token = _latest_invite_token()
    invite = db.session.execute(db.select(StaffInvite)).scalar_one()
    calls = []

    def fake_require(action, token_value=None):
        calls.append((action, token_value))
        if token_value != "fresh-browser-token":
            raise TurnstileError("fake stale provider detail")

    monkeypatch.setattr("app.admin.services.require_turnstile", fake_require)

    missing = admin_client.post(
        f"/invites/accept/{token}/start",
        json=_staff_invite_start_payload(),
    )
    stale = admin_client.post(
        f"/invites/accept/{token}/start",
        data=_staff_invite_start_payload(
            full_name="Safe Recipient",
            phone_number="92345678",
            turnstile_token="stale-browser-token",
        ),
    )
    db.session.refresh(invite)

    assert missing.status_code == 400
    assert missing.get_json() == {"error": "Complete the security challenge before starting setup."}
    assert stale.status_code == 400
    stale_body = stale.get_data(as_text=True)
    assert "Complete the security challenge before starting setup." in stale_body
    assert 'value="Safe Recipient"' in stale_body
    assert 'value="92345678"' in stale_body
    assert invite.status == "pending"
    assert invite.setup_user_id is None
    assert db.session.query(User).count() == 1

    valid = admin_client.post(
        f"/invites/accept/{token}/start",
        data=_staff_invite_start_payload(**{"cf-turnstile-response": "fresh-browser-token"}),
    )
    db.session.refresh(invite)
    failure_metadata = [
        event.event_metadata
        for event in db.session.query(SecurityAuditEvent)
        .filter_by(event_type="staff_invite_accept", outcome="failure")
        .order_by(SecurityAuditEvent.id)
        .all()
    ]
    rendered_payloads = "\n".join(
        (
            missing.get_data(as_text=True),
            stale_body,
            valid.get_data(as_text=True),
            json.dumps(failure_metadata, default=str),
            caplog.text,
        )
    )

    assert valid.status_code == 200
    assert invite.status == "totp_pending"
    assert calls == [
        ("admin_invite_accept", None),
        ("admin_invite_accept", "stale-browser-token"),
        ("admin_invite_accept", "fresh-browser-token"),
    ]
    assert failure_metadata == [{"reason": "turnstile_failed"}, {"reason": "turnstile_failed"}]
    for forbidden in (
        "stale-browser-token",
        "fresh-browser-token",
        "fake stale provider detail",
        STAFF_PASSWORD,
    ):
        assert forbidden not in rendered_payloads


def test_invite_setup_form_disables_submit_until_managed_turnstile_succeeds(
    admin_app,
    admin_client,
):
    admin_app.config["TURNSTILE_ENABLED"] = True
    admin_app.config["TURNSTILE_SITE_KEY"] = "fake-site-key"
    admin_app.config["TURNSTILE_SECRET_KEY"] = "turnstile-secret"
    _root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret)
    assert _create_invite(admin_client, secret).status_code == 201
    token = _latest_invite_token()

    response = admin_client.get(f"/invites/accept/{token}")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert 'data-invite-accept-start' in body
    assert 'data-turnstile-required="true"' in body
    assert 'name="turnstile_token" value="" data-turnstile-response' in body
    assert 'data-callback="sitbankInviteTurnstileSuccess"' in body
    assert 'data-expired-callback="sitbankInviteTurnstileExpired"' in body
    assert 'data-error-callback="sitbankInviteTurnstileError"' in body
    assert 'data-timeout-callback="sitbankInviteTurnstileTimeout"' in body
    assert 'data-before-interactive-callback="sitbankInviteTurnstileInteractiveStart"' in body
    assert 'data-after-interactive-callback="sitbankInviteTurnstileInteractiveEnd"' in body
    assert 'data-unsupported-callback="sitbankInviteTurnstileError"' in body
    assert '<button class="button full" type="submit" data-invite-start-submit disabled' in body
    assert "Complete the security challenge to enable setup." in body
    assert 'js/admin-invite-accept.js' in body
    assert body.index("js/admin-invite-accept.js") < body.index(
        "https://challenges.cloudflare.com/turnstile/v0/api.js"
    )
    assert 'js/admin-invite-accept.js" defer' not in body


def test_turnstile_verifier_rejects_non_https_verify_url(admin_app):
    from app.security.turnstile import TurnstileError, verify_turnstile_token

    admin_app.config["TURNSTILE_ENABLED"] = True
    admin_app.config["TURNSTILE_SECRET_KEY"] = "turnstile-secret"
    admin_app.config["TURNSTILE_VERIFY_URL"] = "file:///tmp/not-a-verifier"

    with admin_app.test_request_context("/invites/accept/token/start", method="POST"):
        with pytest.raises(TurnstileError):
            verify_turnstile_token("browser-token")


def test_invite_info_returns_minimal_metadata_and_no_store_headers(admin_client):
    _root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret)
    assert _create_invite(admin_client, secret).status_code == 201
    token = _latest_invite_token()

    browser_response = admin_client.get(f"/invites/accept/{token}")
    response = _invite_info_json(admin_client, token)
    payload = response.get_json()

    assert browser_response.status_code == 200
    assert browser_response.mimetype == "text/html"
    assert "Set up your staff access" in browser_response.get_data(as_text=True)
    assert response.status_code == 200
    assert payload == {"message": "Invite can be accepted"}
    forbidden_response_text = (
        "workplace_email",
        "role",
        "status",
        "expires_at",
        "acceptance_started",
        "acceptance_locked",
        "acceptance_start_count",
        "acceptance_verify_count",
        "acceptance_locked_at",
        "acceptance_verify_locked_at",
        "setup_user",
        "setup_user_id",
        "used_by_user_id",
        "revoked_by_user_id",
    )
    for forbidden in forbidden_response_text:
        assert forbidden not in payload
        assert forbidden not in response.get_data(as_text=True)
        assert forbidden not in browser_response.get_data(as_text=True)
    assert "staff.person@sit.singaporetech.edu.sg" not in response.get_data(as_text=True)
    assert "staff.person@sit.singaporetech.edu.sg" not in browser_response.get_data(as_text=True)
    _assert_invite_acceptance_security_headers(response)
    _assert_invite_acceptance_security_headers(browser_response)


def test_browser_invite_onboarding_requires_csrf_and_activates_only_after_both_codes(
    admin_app,
    admin_client,
):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, root_secret)
    assert _create_invite(admin_client, root_secret).status_code == 201
    token = _latest_invite_token()
    invite = db.session.execute(db.select(StaffInvite)).scalar_one()
    recipient = admin_app.test_client()
    original_csrf = admin_app.config["WTF_CSRF_ENABLED"]
    admin_app.config["WTF_CSRF_ENABLED"] = True

    try:
        landing = recipient.get(f"/invites/accept/{token}")
        db.session.refresh(invite)
        assert landing.status_code == 200
        assert landing.mimetype == "text/html"
        assert invite.status == "pending"
        assert invite.setup_user_id is None
        assert db.session.query(User).count() == 1

        missing_csrf = recipient.post(
            f"/invites/accept/{token}/start",
            data=_staff_invite_start_payload(),
        )
        missing_csrf_body = missing_csrf.get_data(as_text=True)
        assert missing_csrf.status_code == 400
        assert "Security token expired or invalid. Review the form and try again." in missing_csrf_body
        assert "Private admin request status" not in missing_csrf_body
        assert 'value="Staff Person"' in missing_csrf_body
        assert 'value="91234568"' in missing_csrf_body
        assert STAFF_PASSWORD not in missing_csrf_body
        assert invite.status == "pending"
        csrf_event = db.session.query(SecurityAuditEvent).filter_by(
            event_type="staff_invite_accept",
            outcome="failure",
        ).one()
        assert csrf_event.event_metadata == {
            "reason": "csrf_or_session_failed",
            "phase": "start",
        }

        start_payload = _staff_invite_start_payload(
            csrf_token=_csrf_token_from(landing),
        )
        start = recipient.post(
            f"/invites/accept/{token}/start",
            data=start_payload,
        )
        start_body = start.get_data(as_text=True)
        secret_match = re.search(
            r'id="invite-manual-entry-secret"[^>]*value="([A-Z2-7]+)"',
            start_body,
        )
        assert start.status_code == 200
        assert start.mimetype == "text/html"
        assert secret_match is not None
        assert "Verify your staff access" in start_body
        _assert_invite_acceptance_security_headers(start)

        workplace_code = _latest_workplace_code()
        verify = recipient.post(
            f"/invites/accept/{token}/verify",
            data={
                "csrf_token": _csrf_token_from(start),
                "totp_code": _stable_totp(secret_match.group(1)),
                "workplace_verification_code": workplace_code,
            },
        )
    finally:
        admin_app.config["WTF_CSRF_ENABLED"] = original_csrf

    staff_user = db.session.execute(
        db.select(User).where(User.email == "staff.person@sit.singaporetech.edu.sg")
    ).scalar_one()
    db.session.refresh(invite)
    staff_page = admin_client.get("/staff")

    assert verify.status_code == 200
    assert "Staff access activated" in verify.get_data(as_text=True)
    assert staff_user.account_status == "active"
    assert staff_user.mfa_enabled is True
    assert staff_user.workplace_email_verified_at is not None
    assert invite.status == "accepted"
    assert invite.used_by_user_id == staff_user.id
    assert "staff.person@sit.singaporetech.edu.sg" in staff_page.get_data(as_text=True)
    _assert_invite_acceptance_security_headers(verify)


@pytest.mark.parametrize(
    ("payload_overrides", "expected_message", "expected_reason"),
    [
        ({"full_name": "<Bad Name>"}, "Invalid full name", "invalid_full_name"),
        (
            {"phone_number": "+65 9123 4568"},
            "Enter an 8-digit Singapore mobile number starting with 8 or 9.",
            "invalid_phone",
        ),
        (
            {"confirm_password": f"{STAFF_PASSWORD} different"},
            "Passwords must match.",
            "password_mismatch",
        ),
        (
            {"password": "short", "confirm_password": "short"},
            "Use a password that meets the staff password policy.",
            "password_policy",
        ),
    ],
)
def test_browser_invite_start_validation_failures_are_safe_and_audited(
    admin_client,
    payload_overrides,
    expected_message,
    expected_reason,
):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, root_secret)
    assert _create_invite(admin_client, root_secret).status_code == 201
    token = _latest_invite_token()
    invite = db.session.execute(db.select(StaffInvite)).scalar_one()
    payload = _staff_invite_start_payload(turnstile_token="browser-token", **payload_overrides)

    response = admin_client.post(f"/invites/accept/{token}/start", data=payload)
    body = response.get_data(as_text=True)
    db.session.refresh(invite)
    event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="staff_invite_accept",
        outcome="failure",
    ).one()

    assert response.status_code == 400
    assert expected_message in body
    assert invite.status == "pending"
    assert invite.setup_user_id is None
    assert db.session.query(User).count() == 1
    assert event.event_metadata["reason"] == expected_reason
    assert STAFF_PASSWORD not in body
    assert "browser-token" not in body
    assert "turnstile_token" not in json.dumps(event.event_metadata, default=str)


def test_browser_invite_turnstile_failure_preserves_only_safe_fields(
    admin_client,
    monkeypatch,
):
    from app.security.turnstile import TurnstileError

    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, root_secret)
    assert _create_invite(admin_client, root_secret).status_code == 201
    token = _latest_invite_token()
    invite = db.session.execute(db.select(StaffInvite)).scalar_one()

    def fail_turnstile(_action, _token=None):
        raise TurnstileError("fake provider detail")

    monkeypatch.setattr("app.admin.services.require_turnstile", fail_turnstile)

    response = admin_client.post(
        f"/invites/accept/{token}/start",
        data=_staff_invite_start_payload(
            full_name="Safe Recipient",
            phone_number="92345678",
            turnstile_token="fresh-browser-token",
        ),
    )
    body = response.get_data(as_text=True)
    db.session.refresh(invite)
    event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="staff_invite_accept",
        outcome="failure",
    ).one()

    assert response.status_code == 400
    assert "Complete the security challenge before starting setup." in body
    assert 'value="Safe Recipient"' in body
    assert 'value="92345678"' in body
    assert STAFF_PASSWORD not in body
    assert "fresh-browser-token" not in body
    assert "fake provider detail" not in body
    assert invite.status == "pending"
    assert invite.setup_user_id is None
    assert db.session.query(User).count() == 1
    assert event.event_metadata == {"reason": "turnstile_failed"}


def test_invite_start_duplicate_identity_and_delivery_failures_are_safe(
    admin_client,
    monkeypatch,
    caplog,
):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    existing_staff, _existing_secret = _create_staff_identity(
        username="existing-staff",
        email="existing.staff@sit.singaporetech.edu.sg",
        account_type="staff",
        phone_number="92345678",
    )
    _login_admin(admin_client, root_secret)
    assert _create_invite(admin_client, root_secret).status_code == 201
    duplicate_token = _latest_invite_token()
    duplicate_invite = db.session.execute(db.select(StaffInvite)).scalar_one()

    duplicate = admin_client.post(
        f"/invites/accept/{duplicate_token}/start",
        data=_staff_invite_start_payload(phone_number=existing_staff.phone_number),
    )
    db.session.refresh(duplicate_invite)
    duplicate_event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="staff_invite_accept",
        outcome="failure",
    ).one()

    assert duplicate.status_code == 400
    assert "Staff identity details could not be accepted" in duplicate.get_data(as_text=True)
    assert duplicate_invite.status == "pending"
    assert duplicate_invite.setup_user_id is None
    assert duplicate_event.event_metadata == {"reason": "duplicate_identity"}

    fresh_time = _FIXED_TOTP_TIME + 31
    monkeypatch.setattr("app.auth.services.time.time", lambda: fresh_time)
    assert _create_invite(
        admin_client,
        root_secret,
        workplace_email="delivery.fail@sit.singaporetech.edu.sg",
        totp_code=pyotp.TOTP(root_secret, digits=6, interval=30).at(fresh_time),
    ).status_code == 201
    delivery_token = _latest_invite_token()
    delivery_invite = db.session.execute(
        db.select(StaffInvite).where(StaffInvite.workplace_email_normalized == "delivery.fail@sit.singaporetech.edu.sg")
    ).scalar_one()
    delivery_invite_id = delivery_invite.id
    caplog.set_level("WARNING")
    monkeypatch.setattr(
        "app.admin.services.send_security_email",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("smtp down")),
    )

    delivery = admin_client.post(
        f"/invites/accept/{delivery_token}/start",
        data=_staff_invite_start_payload(phone_number="93456789"),
    )
    body = delivery.get_data(as_text=True)
    delivery_invite = db.session.get(StaffInvite, delivery_invite_id)
    reasons = {
        event.event_metadata.get("reason")
        for event in db.session.query(SecurityAuditEvent).filter_by(
            event_type="staff_invite_accept",
            outcome="failure",
        )
    }

    assert delivery.status_code == 503
    assert "Setup could not send the workplace verification code" in body
    assert delivery_invite.status == "pending"
    assert delivery_invite.setup_user_id is None
    assert "workplace_email_delivery_failed" in reasons
    assert delivery_token not in caplog.text
    assert STAFF_PASSWORD not in caplog.text


def test_invite_acceptance_strict_https_csrf_allows_origin_only_referrer(
    admin_app,
    admin_client,
):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, root_secret)
    assert _create_invite(admin_client, root_secret).status_code == 201
    token = _latest_invite_token()
    invite = db.session.execute(db.select(StaffInvite)).scalar_one()
    recipient = admin_app.test_client()
    original_csrf = admin_app.config["WTF_CSRF_ENABLED"]
    original_strict = admin_app.config["WTF_CSRF_SSL_STRICT"]
    admin_app.config["WTF_CSRF_ENABLED"] = True
    admin_app.config["WTF_CSRF_SSL_STRICT"] = True
    base_url = "https://admin.example.test"
    origin_referrer = f"{base_url}/"
    assert token not in origin_referrer

    try:
        landing = recipient.get(f"/invites/accept/{token}", base_url=base_url)
        assert landing.status_code == 200
        _assert_invite_acceptance_security_headers(landing)

        missing_csrf = recipient.post(
            f"/invites/accept/{token}/start",
            base_url=base_url,
            headers={"Referer": origin_referrer},
            data=_staff_invite_start_payload(),
        )
        db.session.refresh(invite)
        assert missing_csrf.status_code == 400
        assert invite.status == "pending"
        assert invite.setup_user_id is None
        assert db.session.query(User).count() == 1

        start = recipient.post(
            f"/invites/accept/{token}/start",
            base_url=base_url,
            headers={"Referer": origin_referrer},
            data=_staff_invite_start_payload(csrf_token=_csrf_token_from(landing)),
        )
        start_body = start.get_data(as_text=True)
        secret_match = re.search(
            r'id="invite-manual-entry-secret"[^>]*value="([A-Z2-7]+)"',
            start_body,
        )
        assert start.status_code == 200
        assert secret_match is not None
        assert "Verify your staff access" in start_body

        missing_verify_csrf = recipient.post(
            f"/invites/accept/{token}/verify",
            base_url=base_url,
            headers={"Referer": origin_referrer},
            data={
                "totp_code": _stable_totp(secret_match.group(1)),
                "workplace_verification_code": _latest_workplace_code(),
            },
        )
        db.session.refresh(invite)
        assert missing_verify_csrf.status_code == 400
        assert invite.status == "totp_pending"

        verify = recipient.post(
            f"/invites/accept/{token}/verify",
            base_url=base_url,
            headers={"Referer": origin_referrer},
            data={
                "csrf_token": _csrf_token_from(start),
                "totp_code": _stable_totp(secret_match.group(1)),
                "workplace_verification_code": _latest_workplace_code(),
            },
        )
    finally:
        admin_app.config["WTF_CSRF_ENABLED"] = original_csrf
        admin_app.config["WTF_CSRF_SSL_STRICT"] = original_strict

    staff_user = db.session.execute(
        db.select(User).where(User.email == "staff.person@sit.singaporetech.edu.sg")
    ).scalar_one()
    db.session.refresh(invite)

    assert verify.status_code == 200
    assert "Staff access activated" in verify.get_data(as_text=True)
    assert staff_user.account_status == "active"
    assert staff_user.mfa_enabled is True
    assert invite.status == "accepted"
    assert invite.used_by_user_id == staff_user.id
    _assert_invite_acceptance_security_headers(verify)


def test_invite_info_closed_tokens_return_generic_errors_and_no_token_audit(admin_client):
    root, _secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    closed_cases = [
        ("expired", {"expires_at": datetime.now(timezone.utc) - timedelta(minutes=1)}),
        ("revoked", {"status": "revoked", "revoked_at": datetime.now(timezone.utc)}),
        ("used", {"status": "accepted", "used_at": datetime.now(timezone.utc)}),
    ]

    missing_token = "MissingInviteToken000000000000000000000000"
    missing = _invite_info_json(admin_client, missing_token)
    assert missing.status_code == 401
    assert missing.get_json() == {"error": "Invite link is invalid or expired"}
    _assert_invite_acceptance_security_headers(missing)

    for index, (case, overrides) in enumerate(closed_cases):
        token = f"ClosedInviteToken{index:02d}0000000000000000000000"
        _insert_invite_for_token(token, root, **overrides)

        response = _invite_info_json(admin_client, token)

        assert response.status_code == 401, case
        assert response.get_json() == {"error": "Invite link is invalid or expired"}
        assert "staff.person@sit.singaporetech.edu.sg" not in response.get_data(as_text=True)
        _assert_invite_acceptance_security_headers(response)

    events = db.session.query(SecurityAuditEvent).filter_by(event_type="staff_invite_invalid_attempt").all()
    serialized_metadata = json.dumps([event.event_metadata for event in events], default=str)
    assert missing_token not in serialized_metadata
    assert "token" not in serialized_metadata.casefold()


def test_browser_invite_info_closed_tokens_render_generic_recipient_page(admin_client):
    root, _secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    closed_cases = [
        ("MissingInviteToken000000000000000000000000", {}),
        ("MalformedInviteToken", None),
        (
            "ExpiredInviteToken000000000000000000000000",
            {"expires_at": datetime.now(timezone.utc) - timedelta(minutes=1)},
        ),
        (
            "RevokedInviteToken000000000000000000000000",
            {"status": "revoked", "revoked_at": datetime.now(timezone.utc)},
        ),
        (
            "AcceptedInviteToken00000000000000000000000",
            {"status": "accepted", "used_at": datetime.now(timezone.utc)},
        ),
        (
            "LockedInviteToken000000000000000000000000",
            {"acceptance_locked_at": datetime.now(timezone.utc), "acceptance_start_count": 3},
        ),
    ]

    for token, overrides in closed_cases:
        if overrides is not None and overrides:
            _insert_invite_for_token(token, root, **overrides)

        response = admin_client.get(f"/invites/accept/{token}")

        _assert_generic_invite_unavailable_page(response, token)

    events = db.session.query(SecurityAuditEvent).filter_by(event_type="staff_invite_invalid_attempt").all()
    serialized_metadata = json.dumps([event.event_metadata for event in events], default=str)
    for token, _overrides in closed_cases:
        assert token not in serialized_metadata
    assert db.session.query(User).count() == 1


def test_invite_info_does_not_reveal_started_or_locked_acceptance_state(admin_client):
    root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret)
    assert _create_invite(admin_client, secret).status_code == 201
    token = _latest_invite_token()

    start = admin_client.post(
        f"/invites/accept/{token}/start",
        json=_staff_invite_start_payload(),
    )
    started_info = _invite_info_json(admin_client, token)
    locked_token = "LockedInviteInfoToken000000000000000000"
    _insert_invite_for_token(
        locked_token,
        root,
        acceptance_locked_at=datetime.now(timezone.utc),
        acceptance_start_count=3,
    )
    locked_info = _invite_info_json(admin_client, locked_token)

    assert start.status_code == 200
    assert started_info.status_code == 200
    assert started_info.get_json() == {"message": "Invite can be accepted"}
    assert "acceptance_" not in started_info.get_data(as_text=True)
    assert "staff.person@sit.singaporetech.edu.sg" not in started_info.get_data(as_text=True)
    assert locked_info.status_code == 401
    assert locked_info.get_json() == {"error": "Invite link is invalid or expired"}
    assert "acceptance_" not in locked_info.get_data(as_text=True)


def test_invite_acceptance_restart_limit_and_root_reset(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, root_secret)
    assert _create_invite(admin_client, root_secret).status_code == 201
    token = _latest_invite_token()

    for index in range(3):
        start = admin_client.post(
            f"/invites/accept/{token}/start",
            json=_staff_invite_start_payload(
                password=f"{STAFF_PASSWORD} {index}",
                confirm_password=f"{STAFF_PASSWORD} {index}",
            ),
        )
        assert start.status_code == 200

    workplace_verification_deliveries = [
        item for item in password_reset_outbox() if item["subject"] == "SITBank workplace email verification code"
    ]
    assert len(workplace_verification_deliveries) == 3

    locked = admin_client.post(
        f"/invites/accept/{token}/start",
        json=_staff_invite_start_payload(
            password=f"{STAFF_PASSWORD} locked",
            confirm_password=f"{STAFF_PASSWORD} locked",
        ),
    )
    invite = db.session.execute(db.select(StaffInvite)).scalar_one()
    setup_user_id = invite.setup_user_id

    assert locked.status_code == 429
    _assert_invite_acceptance_security_headers(locked)
    db.session.refresh(invite)
    assert invite.acceptance_start_count == 3
    assert invite.acceptance_locked_at is not None
    assert len(
        [
            item
            for item in password_reset_outbox()
            if item["subject"] == "SITBank workplace email verification code"
        ]
    ) == 3
    assert setup_user_id is not None

    reset = admin_client.post(
        f"/invites/{invite.id}/reset-acceptance",
        data={"totp_code": _stable_totp(root_secret)},
    )

    assert reset.status_code == 303
    assert reset.headers["Location"].endswith("/invites")
    db.session.refresh(invite)
    assert invite.status == "pending"
    assert invite.acceptance_start_count == 0
    assert invite.acceptance_locked_at is None
    assert invite.acceptance_session_hash is None
    assert invite.setup_user_id is None
    assert db.session.get(User, setup_user_id) is None

    restarted = admin_client.post(
        f"/invites/accept/{token}/start",
        json=_staff_invite_start_payload(
            password=f"{STAFF_PASSWORD} reset",
            confirm_password=f"{STAFF_PASSWORD} reset",
        ),
    )
    assert restarted.status_code == 200


def test_invite_acceptance_reset_returns_json_for_api_clients(admin_client):
    root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, root_secret)
    invite = _insert_invite_for_token(
        "JsonResetInviteToken0000000000000000000",
        root,
        status="totp_pending",
        acceptance_session_hash="1" * 64,
        acceptance_start_count=2,
        acceptance_locked_at=datetime.now(timezone.utc),
    )

    reset = admin_client.post(
        f"/invites/{invite.id}/reset-acceptance",
        json={"totp_code": _stable_totp(root_secret)},
    )

    assert reset.status_code == 200
    assert reset.get_json()["message"] == "Invite acceptance reset"
    db.session.refresh(invite)
    assert invite.status == "pending"
    assert invite.acceptance_session_hash is None
    assert invite.acceptance_locked_at is None


def test_invite_acceptance_reset_rejects_invalid_actors_step_up_and_missing_invites(admin_client):
    from app.admin.services import reset_staff_invite_acceptance
    from app.auth.services import AuthError

    root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    staff, _staff_secret = _create_staff_identity(
        username="staff-user",
        email="staff.user@sit.singaporetech.edu.sg",
        account_type="staff",
        phone_number="91234568",
    )
    invite = _insert_invite_for_token("ResetGuardInviteToken000000000000000000", root)

    with pytest.raises(AuthError) as forbidden:
        reset_staff_invite_acceptance(staff, invite.id, None)
    assert forbidden.value.status_code == 403
    assert forbidden.value.message == "Forbidden"

    with pytest.raises(AuthError) as invalid_step_up:
        reset_staff_invite_acceptance(root, invite.id, "not-a-code")
    assert invalid_step_up.value.status_code == 403
    assert "Fresh MFA verification is required" in invalid_step_up.value.message
    assert "Wait for a new authenticator code" in invalid_step_up.value.message

    other_root, other_root_secret = _create_staff_identity(
        username="second-root-admin",
        email="root2@sit.singaporetech.edu.sg",
        account_type="root_admin",
        phone_number="91234569",
    )
    _login_admin(admin_client, other_root_secret, email=other_root.email)
    missing = admin_client.post(
        f"/invites/{invite.id + 1000}/reset-acceptance",
        json={"totp_code": _stable_totp(other_root_secret)},
    )

    assert missing.status_code == 404
    assert missing.get_json() == {"error": "Invite not found"}


def test_invite_acceptance_reset_blocks_non_resettable_setup_users(admin_client):
    root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    setup_user = User(
        username="active-staff",
        email="staff.person@sit.singaporetech.edu.sg",
        password_hash=hash_password(STAFF_PASSWORD),
        account_type="staff",
        account_status="active",
        full_name="Active Staff",
        phone_number="91234568",
        account_number=None,
        workplace_email_verified_at=datetime.now(timezone.utc),
    )
    db.session.add(setup_user)
    db.session.flush()
    invite = _insert_invite_for_token(
        "NonResettableInviteToken0000000000000000",
        root,
        status="totp_pending",
        setup_user_id=setup_user.id,
        acceptance_session_hash="0" * 64,
        acceptance_start_count=1,
        acceptance_started_at=datetime.now(timezone.utc),
    )
    _login_admin(admin_client, root_secret)

    blocked = admin_client.post(
        f"/invites/{invite.id}/reset-acceptance",
        json={"totp_code": _stable_totp(root_secret)},
    )

    assert blocked.status_code == 409
    assert blocked.get_json() == {"error": "Invite link is invalid or expired"}
    db.session.refresh(invite)
    db.session.refresh(setup_user)
    assert invite.setup_user_id == setup_user.id
    assert setup_user.account_status == "active"


def test_invite_acceptance_verify_rejects_locked_invites(admin_client):
    root, _root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    token = "LockedVerifyInviteToken00000000000000000"
    _insert_invite_for_token(
        token,
        root,
        status="totp_pending",
        acceptance_locked_at=datetime.now(timezone.utc),
        acceptance_start_count=3,
    )

    locked = admin_client.post(
        f"/invites/accept/{token}/verify",
        json={"totp_code": "123456", "workplace_verification_code": "654321"},
    )

    assert locked.status_code == 429
    _assert_invite_acceptance_security_headers(locked)

    start_token = "LockedStartInviteToken000000000000000000"
    _insert_invite_for_token(
        start_token,
        root,
        acceptance_locked_at=datetime.now(timezone.utc),
        acceptance_start_count=3,
    )
    locked_start = admin_client.post(
        f"/invites/accept/{start_token}/start",
        json=_staff_invite_start_payload(),
    )

    assert locked_start.status_code == 429
    _assert_invite_acceptance_security_headers(locked_start)


def test_invite_acceptance_verify_failures_lock_until_root_reset(admin_app, admin_client, monkeypatch):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, root_secret)
    assert _create_invite(admin_client, root_secret).status_code == 201
    token = _latest_invite_token()

    start = admin_client.post(
        f"/invites/accept/{token}/start",
        json=_staff_invite_start_payload(),
    )
    monkeypatch.setattr("app.admin.services._verify_totp_for_user", lambda *_args, **_kwargs: True)
    monkeypatch.setattr("app.admin.services._verify_totp_for_user_outcome", lambda *_args, **_kwargs: "valid")

    failures = []
    for expected_count in range(1, 6):
        failed = admin_client.post(
            f"/invites/accept/{token}/verify",
            json={"totp_code": "123456", "workplace_verification_code": "000000"},
        )
        failures.append(failed.status_code)
        db.session.remove()
        persisted = db.session.execute(db.select(StaffInvite)).scalar_one()
        assert persisted.acceptance_verify_count == expected_count
    invite = db.session.execute(db.select(StaffInvite)).scalar_one()
    invite_id = invite.id
    assert invite.acceptance_verify_locked_at is not None

    fresh_client = admin_app.test_client()
    blocked_verify = fresh_client.post(
        f"/invites/accept/{token}/verify",
        json={"totp_code": "123456", "workplace_verification_code": "000000"},
    )
    blocked_start = fresh_client.post(
        f"/invites/accept/{token}/start",
        json=_staff_invite_start_payload(),
    )
    root_client = admin_app.test_client()
    _login_admin(root_client, root_secret)
    reset = root_client.post(
        f"/invites/{invite_id}/reset-acceptance",
        json={"totp_code": "123456"},
    )
    db.session.remove()
    reset_invite = db.session.get(StaffInvite, invite_id)
    restarted = fresh_client.post(
        f"/invites/accept/{token}/start",
        json=_staff_invite_start_payload(phone_number="92345679"),
    )

    assert start.status_code == 200
    assert failures == [401, 401, 401, 401, 429]
    assert blocked_verify.status_code == 429
    assert blocked_start.status_code == 429
    assert reset.status_code == 200
    assert reset_invite.acceptance_verify_count == 0
    assert reset_invite.acceptance_verify_locked_at is None
    assert restarted.status_code == 200


def test_invite_acceptance_restarts_existing_setup_user_without_legacy_session_hash(admin_client):
    root, _root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    setup_user = User(
        username="legacy-staff",
        email="staff.person@sit.singaporetech.edu.sg",
        password_hash=hash_password(f"{STAFF_PASSWORD} old"),
        account_type="staff",
        account_status="setup_pending",
        full_name="Legacy Staff",
        phone_number="91234568",
        account_number=None,
        staff_personal_email="legacy.staff@example.test",
    )
    db.session.add(setup_user)
    db.session.flush()
    token = "LegacySessionInviteToken000000000000000"
    invite = _insert_invite_for_token(
        token,
        root,
        status="totp_pending",
        setup_user_id=setup_user.id,
        acceptance_session_hash=None,
        acceptance_start_count=1,
        acceptance_started_at=datetime.now(timezone.utc) - timedelta(minutes=5),
    )

    restarted = admin_client.post(
        f"/invites/accept/{token}/start",
        json=_staff_invite_start_payload(
            full_name="Updated Staff",
            phone_number="92345678",
            password=f"{STAFF_PASSWORD} legacy",
            confirm_password=f"{STAFF_PASSWORD} legacy",
        ),
    )

    assert restarted.status_code == 200
    db.session.refresh(invite)
    db.session.refresh(setup_user)
    assert setup_user.full_name == "Updated Staff"
    assert setup_user.phone_number == "92345678"
    assert setup_user.staff_personal_email is None
    assert invite.acceptance_session_hash is not None
    assert invite.acceptance_start_count == 2


def test_invite_acceptance_verification_is_bound_to_start_session(admin_app, admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, root_secret)
    assert _create_invite(admin_client, root_secret).status_code == 201
    token = _latest_invite_token()
    start = admin_client.post(f"/invites/accept/{token}/start", json=_staff_invite_start_payload())
    setup = start.get_json()["totp_setup"]
    workplace_code = _latest_workplace_code()
    totp_code = _stable_totp(setup["manual_entry_secret"])

    second_browser = admin_app.test_client()
    mismatched_session = second_browser.post(
        f"/invites/accept/{token}/verify",
        json={"totp_code": totp_code, "workplace_verification_code": workplace_code},
    )
    original_session = admin_client.post(
        f"/invites/accept/{token}/verify",
        json={"totp_code": totp_code, "workplace_verification_code": workplace_code},
    )

    assert mismatched_session.status_code == 401
    assert mismatched_session.get_json() == {"error": "Invite link is invalid or expired"}
    _assert_invite_acceptance_security_headers(mismatched_session)
    assert original_session.status_code == 200


def test_invite_acceptance_schema_bounds_password_before_service_policy(admin_client, monkeypatch):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, root_secret)
    assert _create_invite(admin_client, root_secret).status_code == 201
    token = _latest_invite_token()

    def fail_if_service_policy_runs(*_args, **_kwargs):
        raise AssertionError(
            "start_invite_acceptance should not run for schema-level password length failures"
        )

    monkeypatch.setattr("app.admin.routes.start_invite_acceptance", fail_if_service_policy_runs)

    too_short = admin_client.post(
        f"/invites/accept/{token}/start",
        json=_staff_invite_start_payload(password="short", confirm_password="short"),
    )
    too_long_password = "A" * 257
    too_long = admin_client.post(
        f"/invites/accept/{token}/start",
        json=_staff_invite_start_payload(password=too_long_password, confirm_password=too_long_password),
    )

    assert too_short.status_code == 400
    assert too_long.status_code == 400
    _assert_invite_acceptance_security_headers(too_short)
    _assert_invite_acceptance_security_headers(too_long)
    assert (
        db.session.query(User).filter_by(email="staff.person@sit.singaporetech.edu.sg").one_or_none()
        is None
    )


def test_staff_invite_acceptance_activates_only_after_workplace_code_and_totp(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, root_secret)
    assert _create_invite(admin_client, root_secret).status_code == 201
    token = _latest_invite_token()

    info = _invite_info_json(admin_client, token)
    forged_start = admin_client.post(
        f"/invites/accept/{token}/start",
        json=_staff_invite_start_payload(
            role="admin",
            workplace_email="attacker@sit.singaporetech.edu.sg",
            personal_email="attacker@example.com",
        ),
    )
    start = admin_client.post(
        f"/invites/accept/{token}/start",
        json=_staff_invite_start_payload(),
    )
    setup = start.get_json()["totp_setup"]
    staff_user = db.session.execute(
        db.select(User).where(User.email == "staff.person@sit.singaporetech.edu.sg")
    ).scalar_one()
    login_before_activation = admin_client.post(
        "/login",
        json={"workplace_email": staff_user.email, "password": STAFF_PASSWORD},
    )
    workplace_code = _latest_workplace_code()
    totp_code = _stable_totp(setup["manual_entry_secret"])
    verify = admin_client.post(
        f"/invites/accept/{token}/verify",
        json={"totp_code": totp_code, "workplace_verification_code": workplace_code},
    )
    reuse = _invite_info_json(admin_client, token)
    db.session.refresh(staff_user)

    assert info.status_code == 200
    assert info.get_json() == {"message": "Invite can be accepted"}
    assert "staff.person@sit.singaporetech.edu.sg" not in info.get_data(as_text=True)
    assert "role" not in info.get_data(as_text=True)
    _assert_invite_acceptance_security_headers(info)
    assert forged_start.status_code == 400
    assert start.status_code == 200
    assert staff_user.account_type == "staff"
    assert staff_user.account_status == "active"
    assert staff_user.account_number is None
    assert staff_user.staff_personal_email is None
    assert staff_user.workplace_email_verified_at is not None
    assert login_before_activation.status_code == 401
    assert verify.status_code == 200
    assert reuse.status_code == 401
    assert db.session.query(User).filter_by(account_type="customer").count() == 0


def test_staff_invite_acceptance_totp_replay_does_not_increment_verify_failures(
    admin_client,
    monkeypatch,
):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, root_secret)
    assert _create_invite(admin_client, root_secret).status_code == 201
    token = _latest_invite_token()

    start = admin_client.post(
        f"/invites/accept/{token}/start",
        json=_staff_invite_start_payload(),
    )
    setup = start.get_json()["totp_setup"]
    invite = db.session.execute(db.select(StaffInvite)).scalar_one()
    workplace_code = _latest_workplace_code()
    monkeypatch.setattr(
        "app.admin.services._verify_totp_for_user_outcome",
        lambda *_args, **_kwargs: "replay",
    )

    replay = admin_client.post(
        f"/invites/accept/{token}/verify",
        json={
            "totp_code": _stable_totp(setup["manual_entry_secret"]),
            "workplace_verification_code": workplace_code,
        },
    )
    db.session.refresh(invite)

    assert replay.status_code == 401
    assert replay.get_json()["error"] == "Invalid authentication code."
    assert invite.acceptance_verify_count == 0
    assert invite.acceptance_verify_locked_at is None
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="staff_totp_setup",
        outcome="failure",
    ).one().event_metadata["reason"] == "totp_replay"


def test_customer_registration_cannot_create_staff_or_admin_roles(client):
    from _auth_flow_helpers import register

    response = register(client)
    forged = client.post(
        "/auth/register",
        json={
            "username": "staff01",
            "email": "staff@sit.singaporetech.edu.sg",
            "full_name": "Staff User",
            "phone_number": "91234568",
            "password": STAFF_PASSWORD,
            "confirm_password": STAFF_PASSWORD,
            "account_type": "admin",
            "role": "admin",
        },
    )
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()

    assert response.status_code == 302
    assert forged.status_code == 400
    assert user.account_type == "customer"
    assert user.account_status == "active"


def test_admin_login_creates_only_admin_session_cookie(admin_app, admin_client):
    _root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )

    response = _login_admin(admin_client, secret)
    cookies = "\n".join(response.headers.getlist("Set-Cookie"))

    assert "__Host-sitbank_admin_session=" in cookies
    assert "__Host-sitbank_session=" not in cookies
    assert admin_client.get("/").status_code == 200


def test_separation_guard_blocks_linked_staff_acting_on_own_customer(admin_app):
    from app.admin.separation import assert_not_self_customer_action
    from app.auth.services import AuthError

    staff, _secret = _create_staff_identity(
        username="staff-user",
        email="staff.user@sit.singaporetech.edu.sg",
        account_type="staff",
        phone_number="91234567",
        personal_email="same.person@gmail.com",
    )
    customer = User(
        username="customer-user",
        email="same.person@gmail.com",
        password_hash=hash_password(STAFF_PASSWORD),
        account_type="customer",
        account_status="active",
        full_name="Same Person",
        phone_number="91234568",
        account_number="012123456000",
    )
    db.session.add(customer)
    db.session.flush()
    db.session.add(
        PersonIdentityLink(
            staff_user_id=staff.id,
            customer_user_id=customer.id,
            created_by_user_id=staff.id,
            verified_at=datetime.now(timezone.utc),
        )
    )
    db.session.commit()

    with pytest.raises(AuthError):
        assert_not_self_customer_action(staff, customer, "balance_edit")

    event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="staff_self_customer_action_blocked",
        outcome="blocked",
    ).one()
    assert event.user_id == staff.id
    assert event.event_metadata["action_type"] == "balance_edit"
    assert "012123456000" not in json.dumps(event.event_metadata)
