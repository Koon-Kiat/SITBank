from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app import create_app
from app.extensions import db
from app.security import cloudflare_access
from app.security.cloudflare_access import CloudflareAccessConfigurationError
from conftest import TestConfig


AUDIENCE = "0123456789abcdef0123456789abcdef"
ISSUER = "https://sitbank.cloudflareaccess.com"
KID = "test-cloudflare-access-key"


class StagingAccessConfig(TestConfig):
    DEPLOYMENT_TARGET = "staging"
    STAGING_CLOUDFLARE_ACCESS_JWT_REQUIRED = True
    STAGING_CLOUDFLARE_ACCESS_AUD = AUDIENCE
    STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN = "sitbank.cloudflareaccess.com"
    STAGING_CLOUDFLARE_ACCESS_JWKS_CACHE_TTL_SECONDS = 300


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _integer_base64url(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    return _base64url(value.to_bytes(length, "big"))


def _jwt(
    private_key: rsa.RSAPrivateKey,
    *,
    claims: dict[str, Any] | None = None,
    kid: str = KID,
) -> str:
    now = int(time.time())
    payload = {
        "aud": AUDIENCE,
        "email": "operator@example.com",
        "exp": now + 300,
        "iat": now,
        "iss": ISSUER,
        "nbf": now - 1,
        "sub": "operator-id",
    }
    if claims:
        payload.update(claims)
    header = {"alg": "RS256", "kid": kid, "typ": "JWT"}
    encoded_header = _base64url(
        json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    encoded_payload = _base64url(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = private_key.sign(
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return f"{encoded_header}.{encoded_payload}.{_base64url(signature)}"


@pytest.fixture()
def access_signing_key(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "alg": "RS256",
                "e": _integer_base64url(public_numbers.e),
                "kid": KID,
                "kty": "RSA",
                "n": _integer_base64url(public_numbers.n),
                "use": "sig",
            }
        ]
    }
    cloudflare_access._clear_jwks_cache_for_testing()
    monkeypatch.setattr(
        cloudflare_access,
        "_fetch_jwks_document",
        lambda url: jwks,
    )
    yield private_key
    cloudflare_access._clear_jwks_cache_for_testing()


@pytest.fixture()
def staging_app(access_signing_key):
    app = create_app(StagingAccessConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def test_staging_missing_and_malformed_assertions_fail_closed(staging_app):
    client = staging_app.test_client()

    missing = client.get("/")
    malformed = client.get(
        "/",
        headers={"Cf-Access-Jwt-Assertion": "not-a-jwt"},
    )

    assert missing.status_code == 403
    assert malformed.status_code == 403
    assert b"not-a-jwt" not in malformed.data


@pytest.mark.parametrize(
    "claim_override",
    [
        {"exp": 1},
        {"aud": "wrong-audience-0123456789"},
        {"iss": "https://wrong.cloudflareaccess.com"},
        {"nbf": int(time.time()) + 3600},
    ],
)
def test_staging_rejects_expired_wrong_audience_issuer_and_future_tokens(
    staging_app,
    access_signing_key,
    claim_override,
):
    assertion = _jwt(access_signing_key, claims=claim_override)

    response = staging_app.test_client().get(
        "/",
        headers={"Cf-Access-Jwt-Assertion": assertion},
    )

    assert response.status_code == 403
    assert assertion.encode("ascii") not in response.data


def test_staging_rejects_invalid_signature(staging_app):
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assertion = _jwt(attacker_key)

    response = staging_app.test_client().get(
        "/",
        headers={"Cf-Access-Jwt-Assertion": assertion},
    )

    assert response.status_code == 403


def test_valid_assertion_continues_to_normal_flask_authentication(
    staging_app,
    access_signing_key,
):
    assertion = _jwt(access_signing_key)

    response = staging_app.test_client().get(
        "/dashboard",
        headers={"Cf-Access-Jwt-Assertion": assertion},
    )

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_raw_access_assertion_is_never_logged(
    staging_app,
    caplog,
):
    raw_assertion = "sensitive-access-token.must-not.appear"

    response = staging_app.test_client().get(
        "/",
        headers={"Cf-Access-Jwt-Assertion": raw_assertion},
    )

    assert response.status_code == 403
    assert raw_assertion not in caplog.text
    assert "sensitive-access-token" not in caplog.text


def test_loopback_readiness_does_not_require_access_assertion(staging_app):
    response = staging_app.test_client().get(
        "/health/ready",
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code == 200
    assert response.get_json() == {"status": "ready"}


def test_non_loopback_readiness_still_requires_access_assertion(staging_app):
    response = staging_app.test_client().get(
        "/health/ready",
        environ_base={"REMOTE_ADDR": "203.0.113.10"},
    )

    assert response.status_code == 403


def test_production_customer_and_admin_apps_are_not_affected():
    production_customer = create_app(TestConfig, app_mode="customer")
    staging_admin = create_app(StagingAccessConfig, app_mode="admin")

    assert production_customer.test_client().get("/").status_code == 200
    assert staging_admin.test_client().get("/health/live").status_code == 200
    assert "cloudflare_access_verifier" not in production_customer.extensions
    assert "cloudflare_access_verifier" not in staging_admin.extensions


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("STAGING_CLOUDFLARE_ACCESS_AUD", ""),
        ("STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN", ""),
        ("DEPLOYMENT_TARGET", "production"),
    ],
)
def test_required_staging_config_fails_closed(name, value):
    class InvalidConfig(StagingAccessConfig):
        pass

    setattr(InvalidConfig, name, value)

    with pytest.raises(CloudflareAccessConfigurationError):
        create_app(InvalidConfig)


def test_nginx_preserves_origin_pull_and_forwards_only_assertion():
    nginx = Path("ops/nginx/sitbank-staging.conf").read_text(encoding="utf-8")
    headers = Path("ops/nginx/sitbank-cloudflare-access-headers.conf").read_text(
        encoding="utf-8"
    )

    assert (
        "ssl_client_certificate "
        "/etc/nginx/cloudflare-authenticated-origin-pull-ca.pem;" in nginx
    )
    assert "ssl_verify_client optional;" in nginx
    assert "if ($ssl_client_verify != SUCCESS) { return 403; }" in nginx
    assert (
        "proxy_set_header Cf-Access-Jwt-Assertion "
        "$http_cf_access_jwt_assertion;" in headers
    )
    assert 'proxy_set_header Cf-Access-Authenticated-User-Email "";' in headers
    assert 'proxy_set_header Cf-Access-Client-Id "";' in headers
    assert 'proxy_set_header Cf-Access-Client-Secret "";' in headers
    assert nginx.count(
        "include /etc/nginx/snippets/sitbank-cloudflare-access-headers.conf;"
    ) == 6
    ready = nginx.split("location = /health/ready {", 1)[1].split("}", 1)[0]
    assert "sitbank-cloudflare-access-headers.conf" not in ready
