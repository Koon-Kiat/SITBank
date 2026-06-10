from __future__ import annotations

import pytest

from config import _required_webauthn_origin, _required_webauthn_rp_id


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

    monkeypatch.setenv("WEBAUTHN_RP_ORIGIN", "https://sitbank.duckdns.org")

    with pytest.raises(RuntimeError, match="hostname must match"):
        _required_webauthn_origin("WEBAUTHN_RP_ORIGIN", rp_id="sitbank.duckdns.org")
