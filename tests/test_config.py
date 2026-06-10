from __future__ import annotations

import base64
import json

import pytest

from config import (
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

    monkeypatch.setenv("WEBAUTHN_RP_ORIGIN", "https://scamcentre.duckdns.org")

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
