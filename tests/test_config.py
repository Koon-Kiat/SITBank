from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

import config
from config import (
    _required_b64_32_bytes,
    _required_env_or_file,
    _required_session_hmac_keys,
    _required_webauthn_origin,
    _required_webauthn_rp_id,
)


def test_webauthn_rp_id_must_be_bare_hostname(monkeypatch):
    monkeypatch.setenv("WEBAUTHN_RP_ID", "sitbank.duckdns.org")

    assert _required_webauthn_rp_id("WEBAUTHN_RP_ID") == "sitbank.duckdns.org"

    monkeypatch.setenv("WEBAUTHN_RP_ID", "https://sitbank.duckdns.org")

    with pytest.raises(RuntimeError, match="bare hostname"):
        _required_webauthn_rp_id("WEBAUTHN_RP_ID")


def test_webauthn_origin_must_be_https_and_match_rp_id(monkeypatch):
    monkeypatch.setenv("WEBAUTHN_RP_ORIGIN", "https://sitbank.duckdns.org")

    assert (
        _required_webauthn_origin("WEBAUTHN_RP_ORIGIN", rp_id="sitbank.duckdns.org")
        == "https://sitbank.duckdns.org"
    )

    monkeypatch.setenv("WEBAUTHN_RP_ORIGIN", "http://sitbank.duckdns.org")

    with pytest.raises(RuntimeError, match="HTTPS"):
        _required_webauthn_origin("WEBAUTHN_RP_ORIGIN", rp_id="sitbank.duckdns.org")

    monkeypatch.setenv("WEBAUTHN_RP_ORIGIN", "https://legacy.example.invalid")

    with pytest.raises(RuntimeError, match="hostname must match"):
        _required_webauthn_origin("WEBAUTHN_RP_ORIGIN", rp_id="sitbank.duckdns.org")


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
