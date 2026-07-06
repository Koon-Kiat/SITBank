from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

import config
from config import (
    DEFAULT_DEVELOPMENT_PASSWORD_MIN_LENGTH,
    DEFAULT_ROOT_ADMIN_EMAILS,
    MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS,
    MIN_PRODUCTION_PASSWORD_LENGTH,
    _configured_audit_anchor_path,
    _configured_secret,
    _all_email_domains_allowed,
    _csv_domain_set,
    _csv_env_values,
    _password_reset_base_url,
    _required_b64_32_bytes,
    _required_b64_32_bytes_decoded,
    _required_env_or_file,
    _root_admin_email_set,
    _required_session_hmac_keys,
    root_admin_email_allowlist_failures,
    _validate_audit_anchor_path,
    _validate_password_reset_email_config,
    _validate_payee_cooldown_config,
    _validate_password_length_config,
    _validate_session_absolute_lifetime_config,
)


def test_admin_allowed_email_domains_accept_configured_workplace_domains(monkeypatch):
    monkeypatch.setenv(
        "ADMIN_ALLOWED_EMAIL_DOMAINS",
        "sit.singaporetech.edu.sg, singaporetech.edu.sg",
    )

    assert _csv_domain_set("ADMIN_ALLOWED_EMAIL_DOMAINS", default="ignored.example") == frozenset(
        {"sit.singaporetech.edu.sg", "singaporetech.edu.sg"}
    )


@pytest.mark.parametrize(
    "domain",
    [
        "gmail.com",
        "*.sit.singaporetech.edu.sg",
        "example.com",
        "localhost",
        "sit.singaporetech.edu.sg.",
        "sit.singaporetech.edu.sg/evil",
    ],
)
def test_admin_allowed_email_domains_reject_personal_and_malformed_domains(monkeypatch, domain):
    monkeypatch.setenv("ADMIN_ALLOWED_EMAIL_DOMAINS", domain)

    with pytest.raises(RuntimeError, match="approved workplace email domains"):
        _csv_domain_set("ADMIN_ALLOWED_EMAIL_DOMAINS", default="sit.singaporetech.edu.sg")


def test_root_admin_email_validation_requires_real_allowed_workplace_addresses():
    allowed_domains = frozenset({"sit.singaporetech.edu.sg"})

    assert _all_email_domains_allowed(frozenset({"root1@sit.singaporetech.edu.sg"}), allowed_domains)
    assert not _all_email_domains_allowed(frozenset({"root1@gmail.com"}), allowed_domains)
    assert not _all_email_domains_allowed(frozenset({"root1@sit.singaporetech.edu.sg."}), allowed_domains)


@pytest.mark.parametrize(
    "emails",
    [
        DEFAULT_ROOT_ADMIN_EMAILS,
        tuple(reversed(tuple(DEFAULT_ROOT_ADMIN_EMAILS))),
        tuple(item.upper() for item in DEFAULT_ROOT_ADMIN_EMAILS),
        tuple(f"  {item}  " for item in DEFAULT_ROOT_ADMIN_EMAILS),
    ],
)
def test_root_admin_allowlist_rejects_builtin_default_in_production(emails):
    failures = root_admin_email_allowlist_failures(
        emails,
        allowed_domains=frozenset({"sit.singaporetech.edu.sg"}),
        reject_default=True,
    )

    assert "ROOT_ADMIN_EMAILS must be explicitly configured for production/admin runtime" in failures


@pytest.mark.parametrize(
    ("emails", "expected"),
    [
        (
            [
                "chief1@sit.singaporetech.edu.sg",
                "chief1@sit.singaporetech.edu.sg",
                "chief3@sit.singaporetech.edu.sg",
            ],
            "duplicate",
        ),
        (
            [
                "placeholder@sit.singaporetech.edu.sg",
                "chief2@sit.singaporetech.edu.sg",
                "chief3@sit.singaporetech.edu.sg",
            ],
            "placeholder",
        ),
        (
            [
                "chief1@gmail.com",
                "chief2@sit.singaporetech.edu.sg",
                "chief3@sit.singaporetech.edu.sg",
            ],
            "approved admin workplace domains",
        ),
    ],
)
def test_root_admin_allowlist_rejects_unsafe_entries(emails, expected):
    failures = root_admin_email_allowlist_failures(
        emails,
        allowed_domains=frozenset({"sit.singaporetech.edu.sg"}),
        reject_default=True,
    )

    assert any(expected in failure for failure in failures)


def test_root_admin_allowlist_rejects_malformed_collection_and_placeholder_shapes():
    non_collection_failures = root_admin_email_allowlist_failures(
        "chief1@sit.singaporetech.edu.sg",
        allowed_domains=frozenset({"sit.singaporetech.edu.sg"}),
        reject_default=True,
    )
    empty_entry_failures = root_admin_email_allowlist_failures(
        (
            "chief1@sit.singaporetech.edu.sg",
            "",
            "chief3@sit.singaporetech.edu.sg",
        ),
        allowed_domains=frozenset({"sit.singaporetech.edu.sg"}),
        reject_default=True,
    )
    missing_at_failures = root_admin_email_allowlist_failures(
        (
            "chief1",
            "chief2@sit.singaporetech.edu.sg",
            "chief3@sit.singaporetech.edu.sg",
        ),
        allowed_domains=frozenset({"sit.singaporetech.edu.sg"}),
        reject_default=True,
    )
    placeholder_token_failures = root_admin_email_allowlist_failures(
        (
            "chief1@sit.singaporetech.edu.sg",
            "replace-me@sit.singaporetech.edu.sg",
            "chief3@sit.singaporetech.edu.sg",
        ),
        allowed_domains=frozenset({"sit.singaporetech.edu.sg"}),
        reject_default=True,
    )

    assert non_collection_failures == [
        "ROOT_ADMIN_EMAILS must configure exactly 3 root administrators"
    ]
    assert "ROOT_ADMIN_EMAILS must not contain empty entries" in empty_entry_failures
    assert "ROOT_ADMIN_EMAILS must use approved admin workplace domains" in missing_at_failures
    assert (
        "ROOT_ADMIN_EMAILS must not contain placeholder, demo, or example identities"
        in missing_at_failures
    )
    assert (
        "ROOT_ADMIN_EMAILS must not contain placeholder, demo, or example identities"
        in placeholder_token_failures
    )


@pytest.mark.parametrize(
    "placeholder_email",
    [
        "root8@sit.singaporetech.edu.sg",
        "root-admin8@sit.singaporetech.edu.sg",
        "root_admin8@sit.singaporetech.edu.sg",
        "admin1@sit.singaporetech.edu.sg",
        "demo1@sit.singaporetech.edu.sg",
        "test1@sit.singaporetech.edu.sg",
        "example1@sit.singaporetech.edu.sg",
        "placeholder1@sit.singaporetech.edu.sg",
        "changeme1@sit.singaporetech.edu.sg",
        "replace1@sit.singaporetech.edu.sg",
    ],
)
def test_root_admin_allowlist_rejects_numeric_placeholder_identities(placeholder_email):
    emails = [
        *(f"chief{index}@sit.singaporetech.edu.sg" for index in range(1, 7)),
        placeholder_email,
    ]

    failures = root_admin_email_allowlist_failures(
        emails,
        allowed_domains=frozenset({"sit.singaporetech.edu.sg"}),
        reject_default=True,
        required_count=7,
    )

    assert "ROOT_ADMIN_EMAILS must not contain placeholder, demo, or example identities" in failures
    assert "ROOT_ADMIN_EMAILS must configure exactly" not in " ".join(failures)
    assert "ROOT_ADMIN_EMAILS must use approved admin workplace domains" not in failures


def test_root_admin_allowlist_accepts_explicit_non_placeholder_workplace_set():
    emails = frozenset(
        f"chief{index}@sit.singaporetech.edu.sg"
        for index in range(1, 4)
    )

    assert root_admin_email_allowlist_failures(
        emails,
        allowed_domains=frozenset({"sit.singaporetech.edu.sg"}),
        reject_default=True,
    ) == []


def test_root_admin_allowlist_can_load_from_secret_file(monkeypatch, tmp_path):
    value = ",".join(
        f"chief{index}@sit.singaporetech.edu.sg"
        for index in range(1, 4)
    )
    secret_file = tmp_path / "root_admin_emails"
    secret_file.write_text(value, encoding="utf-8")
    monkeypatch.delenv("ROOT_ADMIN_EMAILS", raising=False)
    monkeypatch.setenv("ROOT_ADMIN_EMAILS_FILE", str(secret_file))

    assert _root_admin_email_set(
        "ROOT_ADMIN_EMAILS",
        default="placeholder@example.test",
        allowed_domains=frozenset({"sit.singaporetech.edu.sg"}),
        app_env="production",
        deployment_target="production",
    ) == frozenset(value.split(","))


def test_root_admin_allowlist_can_load_from_direct_environment(monkeypatch):
    value = ",".join(
        f"chief{index}@sit.singaporetech.edu.sg"
        for index in range(1, 4)
    )
    monkeypatch.setenv("ROOT_ADMIN_EMAILS", value)
    monkeypatch.delenv("ROOT_ADMIN_EMAILS_FILE", raising=False)

    assert _root_admin_email_set(
        "ROOT_ADMIN_EMAILS",
        default="placeholder@example.test",
        allowed_domains=frozenset({"sit.singaporetech.edu.sg"}),
        app_env="production",
        deployment_target="production",
    ) == frozenset(value.split(","))


def test_staging_root_admin_allowlist_requires_exactly_two(monkeypatch):
    value = (
        "stagechief1@sit.singaporetech.edu.sg,"
        "stagechief2@singaporetech.edu.sg"
    )
    monkeypatch.setenv("ROOT_ADMIN_EMAILS", value)
    monkeypatch.delenv("ROOT_ADMIN_EMAILS_FILE", raising=False)

    assert _root_admin_email_set(
        "ROOT_ADMIN_EMAILS",
        default="placeholder@example.test",
        allowed_domains=frozenset(
            {"sit.singaporetech.edu.sg", "singaporetech.edu.sg"}
        ),
        app_env="production",
        deployment_target="staging",
    ) == frozenset(value.split(","))


def test_csv_env_values_normalizes_direct_csv_environment(monkeypatch):
    monkeypatch.setenv("CSV_UNIT_TEST_VALUES", " Alpha , beta,ALPHA ")

    assert _csv_env_values("CSV_UNIT_TEST_VALUES", default="ignored") == (
        "alpha",
        "beta",
        "alpha",
    )


def test_root_admin_allowlist_rejects_direct_and_file(monkeypatch, tmp_path):
    secret_file = tmp_path / "root_admin_emails"
    secret_file.write_text(
        ",".join(
            f"chief{index}@sit.singaporetech.edu.sg"
            for index in range(1, 4)
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ROOT_ADMIN_EMAILS", "chief1@sit.singaporetech.edu.sg")
    monkeypatch.setenv("ROOT_ADMIN_EMAILS_FILE", str(secret_file))

    with pytest.raises(RuntimeError, match="Configure either ROOT_ADMIN_EMAILS or ROOT_ADMIN_EMAILS_FILE"):
        _root_admin_email_set(
            "ROOT_ADMIN_EMAILS",
            default="placeholder@example.test",
            allowed_domains=frozenset({"sit.singaporetech.edu.sg"}),
            app_env="production",
            deployment_target="production",
        )


def test_password_reset_base_url_must_be_https_in_production(monkeypatch):
    monkeypatch.setattr(config, "APP_ENV", "production")
    monkeypatch.setenv("PASSWORD_RESET_BASE_URL", "http://sitbank.pp.ua")

    with pytest.raises(RuntimeError, match="HTTPS"):
        _password_reset_base_url(
            "PASSWORD_RESET_BASE_URL",
            default="https://sitbank.pp.ua",
        )


def _valid_production_email_config(**overrides):
    values = {
        "app_env": "production",
        "password_reset_enabled": True,
        "email_backend": "smtp",
        "email_from": "security@sitbank.example",
        "smtp_host": "smtp.example.test",
        "smtp_use_tls": True,
        "smtp_username": "smtp-user-secret",
        "smtp_password": "smtp-password-secret",
    }
    values.update(overrides)
    return values


def test_production_smtp_email_requires_transport_tls():
    _validate_password_reset_email_config(**_valid_production_email_config())

    with pytest.raises(RuntimeError, match="SMTP_USE_TLS=true") as excinfo:
        _validate_password_reset_email_config(
            **_valid_production_email_config(smtp_use_tls=False)
        )

    message = str(excinfo.value)
    assert "smtp-user-secret" not in message
    assert "smtp-password-secret" not in message


def test_production_smtp_email_requires_host_and_credentials_without_secret_leakage():
    for field_name, expected_message in (
        ("smtp_host", "SMTP_HOST"),
        ("smtp_username", "SMTP_USERNAME"),
        ("smtp_password", "SMTP_PASSWORD"),
    ):
        with pytest.raises(RuntimeError, match=expected_message) as excinfo:
            _validate_password_reset_email_config(
                **_valid_production_email_config(**{field_name: None})
            )

        message = str(excinfo.value)
        assert "smtp-user-secret" not in message
        assert "smtp-password-secret" not in message


def test_production_email_rejects_console_backend():
    with pytest.raises(RuntimeError, match="console is not allowed"):
        _validate_password_reset_email_config(
            **_valid_production_email_config(email_backend="console")
        )


def test_non_production_console_email_backend_remains_allowed():
    _validate_password_reset_email_config(
        app_env="development",
        password_reset_enabled=True,
        email_backend="console",
        email_from="",
        smtp_host="",
        smtp_use_tls=False,
        smtp_username=None,
        smtp_password=None,
    )


def test_production_password_minimum_rejects_short_value_without_secret_leakage():
    with pytest.raises(RuntimeError, match="PASSWORD_MIN_LENGTH") as excinfo:
        _validate_password_length_config(
            app_env="production",
            minimum_length=DEFAULT_DEVELOPMENT_PASSWORD_MIN_LENGTH,
            maximum_chars=256,
        )

    message = str(excinfo.value)
    assert str(MIN_PRODUCTION_PASSWORD_LENGTH) in message
    assert "secret" not in message.lower()
    assert "DATABASE_URL" not in message


def test_production_password_minimum_allows_approved_floor():
    _validate_password_length_config(
        app_env="production",
        minimum_length=MIN_PRODUCTION_PASSWORD_LENGTH,
        maximum_chars=256,
    )


def test_non_production_password_minimum_allows_explicit_short_override():
    _validate_password_length_config(
        app_env="development",
        minimum_length=DEFAULT_DEVELOPMENT_PASSWORD_MIN_LENGTH,
        maximum_chars=256,
    )


def test_password_maximum_must_not_be_below_minimum():
    with pytest.raises(RuntimeError, match="PASSWORD_MAX_CHARS"):
        _validate_password_length_config(
            app_env="development",
            minimum_length=80,
            maximum_chars=64,
        )


def test_production_payee_cooldown_rejects_short_value_without_secret_leakage():
    with pytest.raises(RuntimeError, match="PAYEE_COOLDOWN_SECONDS") as excinfo:
        _validate_payee_cooldown_config(
            app_env="production",
            cooldown_seconds=60,
            min_production_seconds=MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS,
        )

    message = str(excinfo.value)
    assert str(MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS) in message
    assert "secret" not in message.lower()
    assert "DATABASE_URL" not in message


@pytest.mark.parametrize(
    "cooldown_seconds",
    [
        MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS,
        MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS + 1,
    ],
)
def test_production_payee_cooldown_allows_approved_minimum(cooldown_seconds):
    _validate_payee_cooldown_config(
        app_env="production",
        cooldown_seconds=cooldown_seconds,
        min_production_seconds=MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS,
    )


def test_non_production_payee_cooldown_allows_short_value():
    _validate_payee_cooldown_config(
        app_env="development",
        cooldown_seconds=60,
        min_production_seconds=MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS,
    )


def test_session_absolute_lifetimes_allow_documented_defaults():
    _validate_session_absolute_lifetime_config(
        customer_lifetime_seconds=12 * 60 * 60,
        admin_lifetime_seconds=4 * 60 * 60,
        customer_pending_mfa_seconds=5 * 60,
        admin_pending_mfa_seconds=60,
    )


def test_session_absolute_lifetime_rejects_values_not_above_pending_mfa():
    with pytest.raises(RuntimeError, match="CUSTOMER_SESSION_ABSOLUTE_LIFETIME_SECONDS"):
        _validate_session_absolute_lifetime_config(
            customer_lifetime_seconds=300,
            admin_lifetime_seconds=240,
            customer_pending_mfa_seconds=300,
            admin_pending_mfa_seconds=60,
        )

    with pytest.raises(RuntimeError, match="ADMIN_SESSION_ABSOLUTE_LIFETIME_SECONDS"):
        _validate_session_absolute_lifetime_config(
            customer_lifetime_seconds=12 * 60 * 60,
            admin_lifetime_seconds=60,
            customer_pending_mfa_seconds=5 * 60,
            admin_pending_mfa_seconds=60,
        )


def test_admin_absolute_lifetime_cannot_exceed_customer_lifetime():
    with pytest.raises(RuntimeError, match="less than or equal"):
        _validate_session_absolute_lifetime_config(
            customer_lifetime_seconds=4 * 60 * 60,
            admin_lifetime_seconds=12 * 60 * 60,
            customer_pending_mfa_seconds=5 * 60,
            admin_pending_mfa_seconds=60,
        )


def test_session_lookup_hmac_key_decodes_to_32_bytes(monkeypatch):
    encoded = base64.b64encode(b"l" * 32).decode("ascii")
    monkeypatch.setenv(
        "SESSION_LOOKUP_HMAC_KEY",
        encoded,
    )

    assert _required_b64_32_bytes_decoded("SESSION_LOOKUP_HMAC_KEY") == b"l" * 32


def test_runtime_secret_maps_use_session_lookup_key_not_redis_url():
    assert "SESSION_LOOKUP_HMAC_KEY" in config.CUSTOMER_RUNTIME_SECRET_ENV_NAMES
    assert "SESSION_LOOKUP_HMAC_KEY" in config.ADMIN_RUNTIME_SECRET_ENV_NAMES
    assert "REDIS_URL" not in config.CUSTOMER_RUNTIME_SECRET_ENV_NAMES
    assert "REDIS_URL" not in config.ADMIN_RUNTIME_SECRET_ENV_NAMES


def test_session_hmac_keyring_requires_active_32_byte_key(monkeypatch):
    current = base64.b64encode(b"a" * 32).decode("ascii")
    previous = base64.b64encode(b"b" * 32).decode("ascii")
    monkeypatch.setenv(
        "SESSION_HMAC_KEYS_JSON",
        json.dumps({"current": current, "previous": previous}),
    )

    keys = _required_session_hmac_keys(
        "SESSION_HMAC_KEYS_JSON",
        active_key_id="current",
    )

    assert keys == {"current": b"a" * 32, "previous": b"b" * 32}

    with pytest.raises(RuntimeError, match="SESSION_HMAC_ACTIVE_KEY_ID"):
        _required_session_hmac_keys(
            "SESSION_HMAC_KEYS_JSON",
            active_key_id="missing",
        )

    monkeypatch.setenv(
        "SESSION_HMAC_KEYS_JSON",
        json.dumps({"current": base64.b64encode(b"short").decode("ascii")}),
    )
    with pytest.raises(RuntimeError, match="exactly 32 bytes"):
        _required_session_hmac_keys(
            "SESSION_HMAC_KEYS_JSON",
            active_key_id="current",
        )


def test_required_configuration_accepts_direct_or_file_exclusively(monkeypatch, tmp_path):
    secret_file = tmp_path / "secret"
    secret_file.write_text("from-file\n", encoding="utf-8")

    monkeypatch.delenv("CONTAINER_TEST_SECRET", raising=False)
    monkeypatch.setenv("CONTAINER_TEST_SECRET_FILE", str(secret_file))
    assert _required_env_or_file("CONTAINER_TEST_SECRET") == "from-file"

    monkeypatch.setenv("CONTAINER_TEST_SECRET", "direct-value")
    with pytest.raises(RuntimeError, match="not both"):
        _required_env_or_file("CONTAINER_TEST_SECRET")

    monkeypatch.delenv("CONTAINER_TEST_SECRET_FILE")
    assert _required_env_or_file("CONTAINER_TEST_SECRET") == "direct-value"


def test_audit_hmac_key_is_required_and_strong_in_production(monkeypatch):
    monkeypatch.setattr(config, "APP_ENV", "production")
    monkeypatch.delenv("SECURITY_AUDIT_HMAC_KEY", raising=False)
    monkeypatch.delenv("SECURITY_AUDIT_HMAC_KEY_FILE", raising=False)

    with pytest.raises(RuntimeError, match="SECURITY_AUDIT_HMAC_KEY"):
        _configured_secret(
            "SECURITY_AUDIT_HMAC_KEY",
            min_length=32,
            development_default="development-audit-hmac-key-change-before-production",
        )

    monkeypatch.setenv("SECURITY_AUDIT_HMAC_KEY", "short")
    with pytest.raises(RuntimeError, match="at least 32"):
        _configured_secret(
            "SECURITY_AUDIT_HMAC_KEY",
            min_length=32,
            development_default="development-audit-hmac-key-change-before-production",
        )

    monkeypatch.setenv("SECURITY_AUDIT_HMAC_KEY", "production-audit-hmac-key-that-is-long-enough")
    assert _configured_secret(
        "SECURITY_AUDIT_HMAC_KEY",
        min_length=32,
        development_default="development-audit-hmac-key-change-before-production",
    ) == "production-audit-hmac-key-that-is-long-enough"


def test_production_audit_anchor_path_is_required_and_validated(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "APP_ENV", "production")
    monkeypatch.delenv("SECURITY_AUDIT_ANCHOR_PATH", raising=False)

    with pytest.raises(RuntimeError, match="SECURITY_AUDIT_ANCHOR_PATH"):
        _configured_audit_anchor_path()

    anchor_dir = tmp_path / "audit-anchor"
    anchor_dir.mkdir()
    anchor_path = anchor_dir / "security-audit.anchor"
    monkeypatch.setenv("SECURITY_AUDIT_ANCHOR_PATH", str(anchor_path))

    assert _configured_audit_anchor_path() == str(anchor_path.resolve())


def test_audit_anchor_path_rejects_unsafe_locations(monkeypatch, tmp_path):
    anchor_dir = tmp_path / "audit-anchor"
    anchor_dir.mkdir()
    anchor_path = anchor_dir / "security-audit.anchor"

    assert _validate_audit_anchor_path("SECURITY_AUDIT_ANCHOR_PATH", str(anchor_path)) == str(
        anchor_path.resolve()
    )

    with pytest.raises(RuntimeError, match="absolute"):
        _validate_audit_anchor_path("SECURITY_AUDIT_ANCHOR_PATH", "relative-anchor.json")

    repo_anchor = Path("security-audit.anchor").resolve()
    with pytest.raises(RuntimeError, match="outside"):
        _validate_audit_anchor_path("SECURITY_AUDIT_ANCHOR_PATH", str(repo_anchor))

    database_dir = tmp_path / "database"
    database_dir.mkdir()
    database_anchor = database_dir / "security-audit.anchor"
    database_url = f"sqlite:///{database_dir / 'app.sqlite'}"
    with pytest.raises(RuntimeError, match="outside"):
        _validate_audit_anchor_path(
            "SECURITY_AUDIT_ANCHOR_PATH",
            str(database_anchor),
            database_url=database_url,
        )

    missing_parent = tmp_path / "missing" / "security-audit.anchor"
    with pytest.raises(RuntimeError, match="parent directory"):
        _validate_audit_anchor_path("SECURITY_AUDIT_ANCHOR_PATH", str(missing_parent))


def test_audit_anchor_path_rejects_world_writable_parent(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX mode bit checks are not reliable on Windows")

    world_writable_dir = tmp_path / "world-writable"
    world_writable_dir.mkdir()
    world_writable_dir.chmod(0o777)

    try:
        with pytest.raises(RuntimeError, match="world-writable"):
            _validate_audit_anchor_path(
                "SECURITY_AUDIT_ANCHOR_PATH",
                str(world_writable_dir / "security-audit.anchor"),
            )
    finally:
        world_writable_dir.chmod(0o700)


def test_secret_file_rejects_empty_multiline_and_symlink(monkeypatch, tmp_path):
    monkeypatch.delenv("CONTAINER_TEST_SECRET", raising=False)

    empty_file = tmp_path / "empty"
    empty_file.write_text("", encoding="utf-8")
    monkeypatch.setenv("CONTAINER_TEST_SECRET_FILE", str(empty_file))
    with pytest.raises(RuntimeError, match="empty"):
        _required_env_or_file("CONTAINER_TEST_SECRET")

    multiline_file = tmp_path / "multiline"
    multiline_file.write_text("line-one\nline-two", encoding="utf-8")
    monkeypatch.setenv("CONTAINER_TEST_SECRET_FILE", str(multiline_file))
    with pytest.raises(RuntimeError, match="control characters"):
        _required_env_or_file("CONTAINER_TEST_SECRET")

    target_file = tmp_path / "target"
    target_file.write_text("secret-value", encoding="utf-8")
    symlink_file = tmp_path / "link"
    try:
        symlink_file.symlink_to(target_file)
    except OSError:
        pytest.skip("Symlink creation is not available on this platform")
    monkeypatch.setenv("CONTAINER_TEST_SECRET_FILE", str(symlink_file))
    with pytest.raises(RuntimeError, match="symlink"):
        _required_env_or_file("CONTAINER_TEST_SECRET")


def test_production_secret_file_must_resolve_beneath_run_secrets(
    monkeypatch,
    tmp_path,
):
    secret_file = tmp_path / "secret"
    secret_file.write_text("secret-value", encoding="utf-8")
    monkeypatch.setattr(config, "APP_ENV", "production")
    monkeypatch.delenv("CONTAINER_TEST_SECRET", raising=False)
    monkeypatch.setenv("CONTAINER_TEST_SECRET_FILE", str(secret_file))

    with pytest.raises(RuntimeError, match="/run/secrets"):
        _required_env_or_file("CONTAINER_TEST_SECRET")


def test_base64_validator_reads_docker_secret_file(monkeypatch, tmp_path):
    key_file = tmp_path / "key"
    key_file.write_text(base64.b64encode(b"k" * 32).decode("ascii"), encoding="utf-8")
    monkeypatch.delenv("CONTAINER_TEST_KEY", raising=False)
    monkeypatch.setenv("CONTAINER_TEST_KEY_FILE", str(key_file))

    assert _required_b64_32_bytes("CONTAINER_TEST_KEY") == (
        base64.b64encode(b"k" * 32).decode("ascii")
    )

    key_file.write_text("not-base64", encoding="utf-8")
    with pytest.raises(RuntimeError, match="valid base64"):
        _required_b64_32_bytes("CONTAINER_TEST_KEY")
