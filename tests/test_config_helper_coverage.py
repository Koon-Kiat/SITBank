from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

import config


def test_secret_file_reader_rejects_unsafe_paths_and_content(tmp_path, monkeypatch):
    with pytest.raises(RuntimeError, match="absolute path"):
        config._read_secret_file("EXAMPLE", "relative")

    missing = tmp_path / "missing"
    with pytest.raises(RuntimeError, match="could not be read"):
        config._read_secret_file("EXAMPLE", str(missing))

    with pytest.raises(RuntimeError, match="regular file"):
        config._read_secret_file("EXAMPLE", str(tmp_path))

    invalid = tmp_path / "invalid"
    invalid.write_bytes(b"\xff")
    with pytest.raises(RuntimeError, match="UTF-8"):
        config._read_secret_file("EXAMPLE", str(invalid))

    empty = tmp_path / "empty"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(RuntimeError, match="is empty"):
        config._read_secret_file("EXAMPLE", str(empty))

    multiline = tmp_path / "multiline"
    multiline.write_text("first\nsecond", encoding="utf-8")
    with pytest.raises(RuntimeError, match="control characters"):
        config._read_secret_file("EXAMPLE", str(multiline))

    valid = tmp_path / "valid"
    valid.write_text("clearly-fake-value\n", encoding="utf-8")
    assert config._read_secret_file("EXAMPLE", str(valid)) == "clearly-fake-value"

    monkeypatch.setattr(Path, "is_symlink", lambda _self: True)
    with pytest.raises(RuntimeError, match="must not be a symlink"):
        config._read_secret_file("EXAMPLE", str(valid))


def test_environment_and_file_loaders_reject_ambiguous_missing_and_placeholder(
    tmp_path,
    monkeypatch,
):
    secret = tmp_path / "secret"
    secret.write_text("clearly-fake-secret-value", encoding="utf-8")
    monkeypatch.setenv("EXAMPLE", "direct")
    monkeypatch.setenv("EXAMPLE_FILE", str(secret))
    with pytest.raises(RuntimeError, match="not both"):
        config._required_env_or_file("EXAMPLE")
    with pytest.raises(RuntimeError, match="not both"):
        config._optional_env_or_file("EXAMPLE")

    monkeypatch.delenv("EXAMPLE")
    assert config._required_env_or_file("EXAMPLE") == "clearly-fake-secret-value"
    assert config._optional_env_or_file("EXAMPLE") == "clearly-fake-secret-value"

    monkeypatch.delenv("EXAMPLE_FILE")
    with pytest.raises(RuntimeError, match="Missing required configuration"):
        config._required_env_or_file("EXAMPLE")
    assert config._optional_env_or_file("EXAMPLE") is None

    monkeypatch.setenv("EXAMPLE", "replace_me_now")
    with pytest.raises(RuntimeError, match="placeholder"):
        config._required_env_or_file("EXAMPLE")
    with pytest.raises(RuntimeError, match="placeholder"):
        config._optional_env_or_file("EXAMPLE")
    with pytest.raises(RuntimeError, match="placeholder"):
        config._required_env("EXAMPLE")

    monkeypatch.setenv("EXAMPLE", "short")
    with pytest.raises(RuntimeError, match="at least 10"):
        config._required_secret("EXAMPLE", min_length=10)
    with pytest.raises(RuntimeError, match="at least 10"):
        config._configured_secret(
            "EXAMPLE",
            min_length=10,
            development_default="long-development-value",
        )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, True),
        ("true", True),
        ("YES", True),
        ("1", True),
        ("false", False),
        ("off", False),
        ("0", False),
    ],
)
def test_optional_bool_accepts_documented_values(monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv("BOOL_VALUE", raising=False)
    else:
        monkeypatch.setenv("BOOL_VALUE", value)
    assert config._optional_bool("BOOL_VALUE", default=True) is expected


def test_scalar_choice_csv_domain_and_email_helpers(monkeypatch):
    monkeypatch.setenv("BOOL_VALUE", "maybe")
    with pytest.raises(RuntimeError, match="boolean"):
        config._optional_bool("BOOL_VALUE", default=False)

    monkeypatch.setenv("CHOICE", "other")
    with pytest.raises(RuntimeError, match="must be one of"):
        config._choice_env("CHOICE", default="one", choices={"one", "two"})

    monkeypatch.setenv("CSV", " , ")
    with pytest.raises(RuntimeError, match="at least one"):
        config._csv_env_set("CSV", default="value")

    assert config._valid_config_domain("sit.singaporetech.edu.sg", reject_personal=True)
    for invalid in ("", "replace_me", "example.com", "*.example.test", "gmail.com"):
        assert not config._valid_config_domain(invalid, reject_personal=True)
    assert config._valid_config_email("user@sit.singaporetech.edu.sg")
    for invalid in ("", "user@gmail.com", "bad", "user@example.com"):
        assert not config._valid_config_email(invalid)
    assert config._email_domain("User@SIT.SingaporeTech.edu.sg") == (
        "sit.singaporetech.edu.sg"
    )
    assert config._email_domain("invalid") == ""


def test_numeric_and_url_helpers_fail_closed(monkeypatch):
    monkeypatch.setenv("FLOAT_VALUE", "bad")
    with pytest.raises(RuntimeError, match="number"):
        config._float_env("FLOAT_VALUE", default="1", minimum=0, maximum=2)
    monkeypatch.setenv("FLOAT_VALUE", "3")
    with pytest.raises(RuntimeError, match="between 0 and 2"):
        config._float_env("FLOAT_VALUE", default="1", minimum=0, maximum=2)

    monkeypatch.setenv("INT_VALUE", "bad")
    with pytest.raises(RuntimeError, match="integer"):
        config._int_env("INT_VALUE", default="1", minimum=0, maximum=2)
    monkeypatch.setenv("INT_VALUE", "3")
    with pytest.raises(RuntimeError, match="between 0 and 2"):
        config._int_env("INT_VALUE", default="1", minimum=0, maximum=2)

    with pytest.raises(RuntimeError, match="schemes"):
        config._validate_url(
            "DATABASE_URL",
            "http://user:pass@example.test/db",
            schemes={"postgresql+psycopg2"},
            require_password=True,
        )
    with pytest.raises(RuntimeError, match="real host"):
        config._validate_url("URL", "https:///path", schemes={"https"}, require_password=False)
    with pytest.raises(RuntimeError, match="include credentials"):
        config._validate_url(
            "DATABASE_URL",
            "postgresql+psycopg2://user@example.test/db",
            schemes={"postgresql+psycopg2"},
            require_password=True,
        )
    with pytest.raises(RuntimeError, match="username and database"):
        config._validate_url(
            "DATABASE_URL",
            "postgresql+psycopg2://:pass@example.test/",
            schemes={"postgresql+psycopg2"},
            require_password=False,
        )


def test_password_reset_url_and_keyring_validation(monkeypatch):
    monkeypatch.setenv("RESET_URL", "not-a-url")
    with pytest.raises(RuntimeError, match="HTTP or HTTPS"):
        config._password_reset_base_url("RESET_URL", default=None)
    monkeypatch.setenv("RESET_URL", "https://user:pass@example.test/path?query=yes")
    with pytest.raises(RuntimeError, match="must not include credentials"):
        config._password_reset_base_url("RESET_URL", default=None)
    monkeypatch.delenv("RESET_URL")
    assert config._password_reset_base_url("RESET_URL", default=None) is None
    assert config._password_reset_base_url(
        "RESET_URL",
        default="https://example.test/base/",
    ) == "https://example.test/base"

    monkeypatch.setenv("B64_KEY", "bad")
    with pytest.raises(RuntimeError, match="valid base64"):
        config._required_b64_32_bytes("B64_KEY")
    monkeypatch.setenv("B64_KEY", base64.b64encode(b"short").decode())
    with pytest.raises(RuntimeError, match="exactly 32 bytes"):
        config._required_b64_32_bytes("B64_KEY")
    encoded = base64.b64encode(b"x" * 32).decode()
    monkeypatch.setenv("B64_KEY", encoded)
    assert config._required_b64_32_bytes_decoded("B64_KEY") == b"x" * 32

    monkeypatch.setenv("KEYRING", "{")
    with pytest.raises(RuntimeError, match="JSON object"):
        config._required_keyring("KEYRING", active_key_id="active", active_label="ACTIVE")
    monkeypatch.setenv("KEYRING", "[]")
    with pytest.raises(RuntimeError, match="at least one key"):
        config._required_keyring("KEYRING", active_key_id="active", active_label="ACTIVE")
    monkeypatch.setenv("KEYRING", json.dumps({"bad key": encoded}))
    with pytest.raises(RuntimeError, match="invalid key identifier"):
        config._required_keyring("KEYRING", active_key_id="active", active_label="ACTIVE")
    monkeypatch.setenv("KEYRING", json.dumps({"active": "bad"}))
    with pytest.raises(RuntimeError, match="valid base64"):
        config._required_keyring("KEYRING", active_key_id="active", active_label="ACTIVE")
    monkeypatch.setenv("KEYRING", json.dumps({"active": base64.b64encode(b"short").decode()}))
    with pytest.raises(RuntimeError, match="exactly 32 bytes"):
        config._required_keyring("KEYRING", active_key_id="active", active_label="ACTIVE")
    monkeypatch.setenv("KEYRING", json.dumps({"other": encoded}))
    with pytest.raises(RuntimeError, match="ACTIVE must identify"):
        config._required_keyring("KEYRING", active_key_id="active", active_label="ACTIVE")
    monkeypatch.setenv("KEYRING", json.dumps({"active": encoded}))
    assert config._required_keyring(
        "KEYRING",
        active_key_id="active",
        active_label="ACTIVE",
    ) == {"active": b"x" * 32}


def test_runtime_mode_rejects_unknown_mode():
    with pytest.raises(RuntimeError, match="customer.*admin"):
        config.apply_runtime_mode_config({}, "unknown")


@pytest.mark.parametrize(
    ("minimum", "maximum", "environment", "message"),
    [
        ("bad", 256, "testing", "PASSWORD_MIN_LENGTH must be an integer"),
        (8, "bad", "testing", "PASSWORD_MAX_CHARS must be an integer"),
        (0, 256, "testing", "between 1 and 1024"),
        (8, 10, "testing", "between 64 and 1024"),
        (100, 64, "testing", "at least PASSWORD_MIN_LENGTH"),
        (8, 256, "production", "at least 15"),
    ],
)
def test_password_length_validator_rejects_invalid_bounds(
    minimum,
    maximum,
    environment,
    message,
):
    with pytest.raises(RuntimeError, match=message):
        config._validate_password_length_config(
            app_env=environment,
            minimum_length=minimum,
            maximum_chars=maximum,
        )


@pytest.mark.parametrize(
    ("cooldown", "minimum", "environment", "message"),
    [
        ("bad", 10, "testing", "must be an integer"),
        (10, "bad", "testing", "MIN_PRODUCTION.*integer"),
        (0, 10, "testing", "between 1"),
        (10, 0, "testing", "MIN_PRODUCTION.*between 1"),
        (10, 20, "production", "at least 20"),
    ],
)
def test_payee_cooldown_validator_rejects_invalid_bounds(
    cooldown,
    minimum,
    environment,
    message,
):
    with pytest.raises(RuntimeError, match=message):
        config._validate_payee_cooldown_config(
            app_env=environment,
            cooldown_seconds=cooldown,
            min_production_seconds=minimum,
        )


@pytest.mark.parametrize(
    ("customer", "admin", "customer_pending", "admin_pending", "message"),
    [
        ("bad", 100, 10, 10, "CUSTOMER.*integer"),
        (100, "bad", 10, 10, "ADMIN.*integer"),
        (100, 50, "bad", 10, "PENDING_MFA.*integers"),
        (0, 50, 10, 10, "CUSTOMER.*between 1"),
        (100, 0, 10, 10, "ADMIN.*between 1"),
        (10, 5, 10, 1, "CUSTOMER.*greater"),
        (100, 5, 10, 5, "ADMIN.*greater"),
        (100, 101, 10, 10, "less than or equal"),
    ],
)
def test_session_lifetime_validator_rejects_invalid_relationships(
    customer,
    admin,
    customer_pending,
    admin_pending,
    message,
):
    with pytest.raises(RuntimeError, match=message):
        config._validate_session_absolute_lifetime_config(
            customer_lifetime_seconds=customer,
            admin_lifetime_seconds=admin,
            customer_pending_mfa_seconds=customer_pending,
            admin_pending_mfa_seconds=admin_pending,
        )


def test_optional_url_turnstile_and_email_config_error_branches(tmp_path, monkeypatch):
    value_file = tmp_path / "value"
    value_file.write_text("https://example.test/path", encoding="utf-8")
    monkeypatch.setenv("OPTIONAL_URL", "https://example.test")
    monkeypatch.setenv("OPTIONAL_URL_FILE", str(value_file))
    with pytest.raises(RuntimeError, match="not both"):
        config._optional_url("OPTIONAL_URL", schemes={"https"}, require_password=False)
    monkeypatch.delenv("OPTIONAL_URL")
    assert config._optional_url(
        "OPTIONAL_URL",
        schemes={"https"},
        require_password=False,
    ) == "https://example.test/path"
    monkeypatch.delenv("OPTIONAL_URL_FILE")
    assert config._optional_url(
        "OPTIONAL_URL",
        schemes={"https"},
        require_password=False,
    ) is None
    monkeypatch.setenv("OPTIONAL_URL", "replace_me")
    with pytest.raises(RuntimeError, match="placeholder"):
        config._optional_url("OPTIONAL_URL", schemes={"https"}, require_password=False)

    monkeypatch.setenv("TURNSTILE_SECRET_KEY", "direct")
    monkeypatch.setenv("TURNSTILE_SECRET_KEY_FILE", str(value_file))
    with pytest.raises(RuntimeError, match="not both"):
        config._optional_turnstile_secret()
    monkeypatch.delenv("TURNSTILE_SECRET_KEY")
    assert config._optional_turnstile_secret() == "https://example.test/path"
    monkeypatch.delenv("TURNSTILE_SECRET_KEY_FILE")
    assert config._optional_turnstile_secret() is None
    monkeypatch.setenv("TURNSTILE_SECRET_KEY", "replace_me")
    with pytest.raises(RuntimeError, match="placeholder"):
        config._optional_turnstile_secret()

    with pytest.raises(RuntimeError, match="PASSWORD_RESET_EMAIL_FROM"):
        config._validate_password_reset_email_config(
            app_env="production",
            password_reset_enabled=True,
            email_backend="smtp",
            email_from="",
            smtp_host="smtp.example.test",
            smtp_use_tls=True,
            smtp_username="fake",
            smtp_password="fake",
        )
