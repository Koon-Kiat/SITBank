from __future__ import annotations

import base64
import ipaddress
import json
import math
import re
import threading
import time
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import Flask, abort, g, request


_AUDIENCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_TEAM_DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)"
    r"+cloudflareaccess\.com$",
    re.IGNORECASE,
)
_BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_ASSERTION_LENGTH = 16 * 1024
_MAX_JWKS_BYTES = 256 * 1024
_JWKS_CACHE: dict[str, tuple[float, dict[str, rsa.RSAPublicKey]]] = {}
_JWKS_CACHE_LOCK = threading.Lock()


class CloudflareAccessConfigurationError(RuntimeError):
    """Raised when the staging Access assertion gate is configured unsafely."""


class CloudflareAccessVerificationError(ValueError):
    """Raised for all untrusted or unverifiable Access assertions."""


@dataclass(frozen=True)
class CloudflareAccessSettings:
    required: bool
    audience: str
    issuer: str
    jwks_url: str
    jwks_cache_ttl_seconds: int


def _required_bool(config: Mapping[str, Any], name: str) -> bool:
    value = config.get(name, False)
    if not isinstance(value, bool):
        raise CloudflareAccessConfigurationError(f"{name} must be a boolean")
    return value


def _team_domain(value: Any) -> str:
    domain = str(value or "").strip().lower().rstrip(".")
    if domain.startswith("https://"):
        domain = domain.removeprefix("https://").rstrip("/")
    if not _TEAM_DOMAIN_PATTERN.fullmatch(domain):
        raise CloudflareAccessConfigurationError(
            "STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN must be a "
            "*.cloudflareaccess.com hostname"
        )
    return domain


def cloudflare_access_settings(
    config: Mapping[str, Any],
    *,
    app_mode: str,
) -> CloudflareAccessSettings:
    required = _required_bool(config, "STAGING_CLOUDFLARE_ACCESS_JWT_REQUIRED")
    if app_mode != "customer" or not required:
        return CloudflareAccessSettings(False, "", "", "", 0)

    target = str(config.get("DEPLOYMENT_TARGET") or "").strip().casefold()
    if target != "staging":
        raise CloudflareAccessConfigurationError(
            "Cloudflare Access JWT enforcement is permitted only for staging"
        )

    audience = str(config.get("STAGING_CLOUDFLARE_ACCESS_AUD") or "").strip()
    if not _AUDIENCE_PATTERN.fullmatch(audience):
        raise CloudflareAccessConfigurationError(
            "STAGING_CLOUDFLARE_ACCESS_AUD is missing or invalid"
        )
    domain = _team_domain(config.get("STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN"))
    try:
        cache_ttl = int(
            config.get("STAGING_CLOUDFLARE_ACCESS_JWKS_CACHE_TTL_SECONDS", 300)
        )
    except (TypeError, ValueError) as exc:
        raise CloudflareAccessConfigurationError(
            "STAGING_CLOUDFLARE_ACCESS_JWKS_CACHE_TTL_SECONDS must be an integer"
        ) from exc
    if cache_ttl < 60 or cache_ttl > 3600:
        raise CloudflareAccessConfigurationError(
            "STAGING_CLOUDFLARE_ACCESS_JWKS_CACHE_TTL_SECONDS must be between 60 and 3600"
        )

    issuer = f"https://{domain}"
    return CloudflareAccessSettings(
        required=True,
        audience=audience,
        issuer=issuer,
        jwks_url=f"{issuer}/cdn-cgi/access/certs",
        jwks_cache_ttl_seconds=cache_ttl,
    )


def validate_cloudflare_access_config(
    config: Mapping[str, Any],
    *,
    app_mode: str,
) -> None:
    cloudflare_access_settings(config, app_mode=app_mode)


def _decode_base64url(segment: str, *, label: str) -> bytes:
    if not segment or not _BASE64URL_PATTERN.fullmatch(segment):
        raise CloudflareAccessVerificationError(f"Invalid JWT {label}")
    try:
        return base64.urlsafe_b64decode(segment + ("=" * (-len(segment) % 4)))
    except ValueError as exc:
        raise CloudflareAccessVerificationError(f"Invalid JWT {label}") from exc


def _decode_json_segment(segment: str, *, label: str) -> dict[str, Any]:
    raw = _decode_base64url(segment, label=label)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CloudflareAccessVerificationError(f"Invalid JWT {label}") from exc
    if not isinstance(value, dict):
        raise CloudflareAccessVerificationError(f"Invalid JWT {label}")
    return value


def _integer_from_base64url(value: Any, *, label: str) -> int:
    if not isinstance(value, str):
        raise CloudflareAccessVerificationError(f"Invalid JWKS {label}")
    raw = _decode_base64url(value, label=f"JWKS {label}")
    if not raw:
        raise CloudflareAccessVerificationError(f"Invalid JWKS {label}")
    return int.from_bytes(raw, "big")


def _parse_jwks(document: Any) -> dict[str, rsa.RSAPublicKey]:
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise CloudflareAccessVerificationError("Invalid Cloudflare Access JWKS")

    keys: dict[str, rsa.RSAPublicKey] = {}
    for item in document["keys"]:
        if not isinstance(item, dict):
            continue
        kid = item.get("kid")
        if (
            not isinstance(kid, str)
            or not kid
            or len(kid) > 128
            or item.get("kty") != "RSA"
            or item.get("alg") not in {None, "RS256"}
            or item.get("use") not in {None, "sig"}
        ):
            continue
        try:
            exponent = _integer_from_base64url(item.get("e"), label="exponent")
            modulus = _integer_from_base64url(item.get("n"), label="modulus")
            key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
        except (TypeError, ValueError):
            continue
        if key.key_size < 2048:
            continue
        keys[kid] = key
    if not keys:
        raise CloudflareAccessVerificationError(
            "Cloudflare Access JWKS contains no usable signing keys"
        )
    return keys


def _fetch_jwks_document(url: str) -> dict[str, Any]:
    request_object = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "SITBank-Cloudflare-Access-Verifier/1",
        },
    )
    try:
        # The URL is derived only from a validated *.cloudflareaccess.com domain.
        with urllib.request.urlopen(  # nosec B310
            request_object,
            timeout=5,
        ) as response:
            raw = response.read(_MAX_JWKS_BYTES + 1)
    except OSError as exc:
        raise CloudflareAccessVerificationError(
            "Cloudflare Access signing keys are unavailable"
        ) from exc
    if len(raw) > _MAX_JWKS_BYTES:
        raise CloudflareAccessVerificationError(
            "Cloudflare Access signing-key response is too large"
        )
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CloudflareAccessVerificationError(
            "Cloudflare Access signing-key response is invalid"
        ) from exc
    if not isinstance(document, dict):
        raise CloudflareAccessVerificationError(
            "Cloudflare Access signing-key response is invalid"
        )
    return document


def _signing_keys(
    settings: CloudflareAccessSettings,
    *,
    force_refresh: bool = False,
) -> dict[str, rsa.RSAPublicKey]:
    now = time.monotonic()
    with _JWKS_CACHE_LOCK:
        cached = _JWKS_CACHE.get(settings.jwks_url)
        if not force_refresh and cached and cached[0] > now:
            return cached[1]
        keys = _parse_jwks(_fetch_jwks_document(settings.jwks_url))
        _JWKS_CACHE[settings.jwks_url] = (
            now + settings.jwks_cache_ttl_seconds,
            keys,
        )
        return keys


def _numeric_date(claims: Mapping[str, Any], name: str) -> float:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CloudflareAccessVerificationError(f"Invalid JWT {name} claim")
    numeric = float(value)
    if not math.isfinite(numeric):
        raise CloudflareAccessVerificationError(f"Invalid JWT {name} claim")
    return numeric


def _audience_matches(value: Any, expected: str) -> bool:
    if isinstance(value, str):
        return value == expected
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return expected in value
    return False


class CloudflareAccessVerifier:
    def __init__(self, settings: CloudflareAccessSettings) -> None:
        if not settings.required:
            raise CloudflareAccessConfigurationError(
                "Cannot construct a verifier when Access JWT enforcement is disabled"
            )
        self._settings = settings

    def verify(
        self,
        assertion: str,
        *,
        now: float | None = None,
    ) -> dict[str, Any]:
        if (
            not isinstance(assertion, str)
            or not assertion
            or len(assertion) > _MAX_ASSERTION_LENGTH
            or any(character.isspace() for character in assertion)
        ):
            raise CloudflareAccessVerificationError("Invalid Access assertion")

        segments = assertion.split(".")
        if len(segments) != 3:
            raise CloudflareAccessVerificationError("Invalid Access assertion")
        encoded_header, encoded_claims, encoded_signature = segments
        header = _decode_json_segment(encoded_header, label="header")
        if header.get("alg") != "RS256":
            raise CloudflareAccessVerificationError("Unsupported JWT algorithm")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid or len(kid) > 128:
            raise CloudflareAccessVerificationError("Invalid JWT key identifier")

        keys = _signing_keys(self._settings)
        key = keys.get(kid)
        if key is None:
            key = _signing_keys(self._settings, force_refresh=True).get(kid)
        if key is None:
            raise CloudflareAccessVerificationError("Unknown JWT signing key")

        signature = _decode_base64url(encoded_signature, label="signature")
        signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
        try:
            key.verify(
                signature,
                signing_input,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except InvalidSignature as exc:
            raise CloudflareAccessVerificationError(
                "Invalid Access assertion signature"
            ) from exc

        claims = _decode_json_segment(encoded_claims, label="claims")
        if claims.get("iss") != self._settings.issuer:
            raise CloudflareAccessVerificationError("Invalid JWT issuer")
        if not _audience_matches(claims.get("aud"), self._settings.audience):
            raise CloudflareAccessVerificationError("Invalid JWT audience")

        current_time = time.time() if now is None else float(now)
        if _numeric_date(claims, "exp") <= current_time:
            raise CloudflareAccessVerificationError("Expired Access assertion")
        if "nbf" in claims and _numeric_date(claims, "nbf") > current_time:
            raise CloudflareAccessVerificationError(
                "Access assertion is not yet valid"
            )
        return claims


def _loopback_readiness_request() -> bool:
    if request.path != "/health/ready":
        return False
    try:
        return ipaddress.ip_address(request.remote_addr or "").is_loopback
    except ValueError:
        return False


def register_cloudflare_access_guard(app: Flask) -> None:
    app_mode = str(app.config.get("APP_MODE") or "").strip().casefold()
    settings = cloudflare_access_settings(app.config, app_mode=app_mode)
    if not settings.required:
        return

    verifier = CloudflareAccessVerifier(settings)
    app.extensions["cloudflare_access_verifier"] = verifier

    @app.before_request
    def require_cloudflare_access_assertion() -> None:
        if _loopback_readiness_request():
            return
        assertion = request.headers.get("Cf-Access-Jwt-Assertion", "")
        try:
            verifier.verify(assertion)
        except CloudflareAccessVerificationError:
            abort(403)
        g.cloudflare_access_verified = True


def _clear_jwks_cache_for_testing() -> None:
    with _JWKS_CACHE_LOCK:
        _JWKS_CACHE.clear()
