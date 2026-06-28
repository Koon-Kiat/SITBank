from __future__ import annotations

import re
from datetime import datetime, timezone

import pyotp
import pytest

from app.extensions import db
from app.models import SecurityAuditEvent, User
from app.security.crypto import encrypt_mfa_secret
from app.security.passwords import hash_password, verify_password
from conftest import TestConfig


ROOT_EMAIL = "root1@sit.singaporetech.edu.sg"


def _credential_input(label: str) -> str:
    return f"SITBank-{label}-Root-Admin-2026!"


@pytest.fixture()
def admin_app(monkeypatch):
    from app import create_app
    from app.security import passwords

    monkeypatch.setattr(passwords, "_is_password_pwned_by_hibp", lambda _password: False)
    flask_app = create_app(TestConfig, app_mode="admin")
    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()


def _command_input(credential: str | None = None) -> str:
    credential = credential or _credential_input("Primary")
    return "\n".join(
        [
            ROOT_EMAIL,
            "root-admin",
            "Root Admin",
            credential,
            credential,
            "",
        ]
    )


def _secret_from_output(output: str) -> str:
    match = re.search(r"Manual entry secret: ([A-Z2-7]+)", output)
    assert match, output
    return match.group(1)


def _login_admin(client, *, credential: str, secret: str, email: str = ROOT_EMAIL):
    password_response = client.post(
        "/login",
        json={"workplace_email": email, "password": credential},
    )
    assert password_response.status_code == 200
    verify_response = client.post(
        "/mfa/verify",
        json={"totp_code": pyotp.TOTP(secret, digits=6, interval=30).now()},
    )
    assert verify_response.status_code == 200
    return verify_response


def _create_existing_root_admin(credential: str) -> tuple[User, str]:
    user = User(
        username="root-admin",
        email=ROOT_EMAIL,
        password_hash=hash_password(credential),
        account_type="root_admin",
        account_status="active",
        full_name="Root Admin",
        phone_number=None,
        account_number=None,
        workplace_email_verified_at=datetime.now(timezone.utc),
        mfa_enabled=True,
    )
    db.session.add(user)
    db.session.flush()
    secret = pyotp.random_base32(length=32)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(secret, user.id)
    db.session.commit()
    return user, secret


def test_bootstrap_root_admin_cli_creates_allowlisted_active_totp_root(admin_app):
    runner = admin_app.test_cli_runner()
    credential = _credential_input("Primary")

    result = runner.invoke(args=["admin", "bootstrap-root"], input=_command_input(credential))

    assert result.exit_code == 0, result.output
    assert credential not in result.output
    assert "ONE-TIME SENSITIVE TOTP SETUP OUTPUT" in result.output
    assert "otpauth://totp/" in result.output
    secret = _secret_from_output(result.output)
    user = db.session.execute(db.select(User).where(User.email == ROOT_EMAIL)).scalar_one()
    assert user.account_type == "root_admin"
    assert user.account_status == "active"
    assert user.workplace_email_verified_at is not None
    assert user.mfa_enabled is True
    assert user.mfa_secret_ciphertext is not None
    assert user.account_number is None
    assert db.session.query(User).filter_by(account_type="root_admin").count() == 1

    _login_admin(admin_app.test_client(), credential=credential, secret=secret)

    event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="root_admin_bootstrap",
        outcome="success",
    ).one()
    assert event.user_id == user.id
    assert event.event_metadata["created"] is True
    assert "manual_entry_secret" not in str(event.event_metadata).casefold()
    assert "otpauth" not in str(event.event_metadata).casefold()


def test_bootstrap_root_admin_cli_requires_root_admin_allowlist(admin_app):
    runner = admin_app.test_cli_runner()
    command_input = _command_input().replace(ROOT_EMAIL, "operator@sit.singaporetech.edu.sg", 1)

    result = runner.invoke(args=["admin", "bootstrap-root"], input=command_input)

    assert result.exit_code != 0
    assert "ROOT_ADMIN_EMAILS" in result.output
    assert db.session.query(User).count() == 0


def test_bootstrap_root_admin_cli_refuses_customer_account_conversion(admin_app):
    credential = _credential_input("Primary")
    customer = User(
        username="root-customer",
        email=ROOT_EMAIL,
        password_hash=hash_password(credential),
        account_type="customer",
        account_status="active",
        full_name="Root Customer",
        phone_number="91234567",
        account_number="123456789",
    )
    db.session.add(customer)
    db.session.commit()

    result = admin_app.test_cli_runner().invoke(
        args=["admin", "bootstrap-root", "--reset-existing"],
        input=_command_input(),
    )

    db.session.refresh(customer)
    assert result.exit_code != 0
    assert "customer account" in result.output
    assert customer.account_type == "customer"
    assert customer.account_number == "123456789"
    assert db.session.query(User).filter_by(account_type="root_admin").count() == 0


def test_bootstrap_root_admin_cli_resets_existing_root_only_with_flag(admin_app):
    old_credential = _credential_input("Prior")
    updated_credential = _credential_input("Rotated")
    user, old_secret = _create_existing_root_admin(old_credential)
    runner = admin_app.test_cli_runner()

    refused = runner.invoke(args=["admin", "bootstrap-root"], input=_command_input(updated_credential))
    accepted = runner.invoke(
        args=["admin", "bootstrap-root", "--reset-existing"],
        input=_command_input(updated_credential),
    )

    assert refused.exit_code != 0
    assert "--reset-existing" in refused.output
    assert accepted.exit_code == 0, accepted.output
    new_secret = _secret_from_output(accepted.output)
    db.session.refresh(user)
    assert db.session.query(User).filter_by(email=ROOT_EMAIL).count() == 1
    assert user.account_type == "root_admin"
    assert user.account_status == "active"
    assert user.mfa_enabled is True
    assert old_secret != new_secret

    assert not verify_password(old_credential, user.password_hash)
    _login_admin(admin_app.test_client(), credential=updated_credential, secret=new_secret)

    event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="root_admin_bootstrap",
        outcome="success",
    ).order_by(SecurityAuditEvent.id.desc()).first()
    assert event is not None
    assert event.event_metadata["created"] is False
    assert event.event_metadata["reset_existing"] is True
