from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import unicodedata
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from flask import current_app

from app.extensions import db
from app.models import SecurityCircuitBreaker


HIBP_RANGE_API_URL = "https://api.pwnedpasswords.com/range"
HIBP_MAX_RESPONSE_BYTES = 256 * 1024
HIBP_UNAVAILABLE_ERROR = (
    "Live breached-password screening is temporarily unavailable. "
    "Please try again later."
)
HIBP_FALLBACK_WARNING = (
    "Live breached-password screening was unavailable; "
    "the local password blocklist was applied."
)
COMMON_PASSWORD_ERROR = "Password is too common. Please try again"
HIBP_CIRCUIT_SERVICE = "hibp_password_check"
PASSWORD_MIN_LENGTH = 8
PASSWORD_RECOMMENDED_MIN_LENGTH = 15
PASSWORD_MAX_CHARS = 256
PBKDF2_PREFIX = "osp-pbkdf2-sha256"
PBKDF2_VERSION = "v1"
PBKDF2_SALT_BYTES = 32
PBKDF2_DERIVED_KEY_BYTES = 32


class PasswordPolicyError(ValueError):
    pass


class LivePasswordCheckUnavailable(RuntimeError):
    pass


@lru_cache(maxsize=4)
def _load_common_passwords(path: str) -> frozenset[str]:
    password_file = Path(path)
    if not password_file.exists():
        raise RuntimeError(f"Common password dictionary does not exist: {path}")
    with password_file.open("r", encoding="utf-8", errors="ignore") as handle:
        passwords = frozenset(
            _normalize_password(line.strip()).casefold()
            for line in handle
            if line.strip() and not line.startswith("#")
        )
    minimum_entries = int(current_app.config["COMMON_PASSWORDS_MIN_ENTRIES"])
    if len(passwords) < minimum_entries:
        raise RuntimeError(
            "Common password dictionary is too small: "
            f"{len(passwords)} entries loaded, {minimum_entries} required"
        )
    return passwords


def validate_password_policy(password: str) -> list[str]:
    if not isinstance(password, str):
        raise PasswordPolicyError("Password is required")

    _ensure_raw_password_length(password)
    normalized_password = _normalize_password(password)
    _ensure_normalized_password_length(normalized_password)
    minimum_length = password_min_length()
    if len(normalized_password) < minimum_length:
        raise PasswordPolicyError(f"Password must be at least {minimum_length} characters")

    common_passwords = _load_common_passwords(current_app.config["COMMON_PASSWORDS_PATH"])
    if normalized_password.casefold() in common_passwords:
        raise PasswordPolicyError(COMMON_PASSWORD_ERROR)

    if _hibp_circuit_is_open():
        return [HIBP_FALLBACK_WARNING]

    try:
        is_pwned = _is_password_pwned_by_hibp(normalized_password)
    except LivePasswordCheckUnavailable as exc:
        _record_hibp_failure()
        current_app.logger.warning(
            "hibp_password_check_unavailable error=%s",
            type(exc).__name__,
        )
        return [HIBP_FALLBACK_WARNING]

    _clear_hibp_failures()
    if is_pwned:
        raise PasswordPolicyError(COMMON_PASSWORD_ERROR)
    return []


def _is_password_pwned_by_hibp(password: str) -> bool:
    # SHA-1 is required by the HIBP range API and is only used as a lookup key.
    password_hash = hashlib.sha1(
        password.encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest().upper()
    hash_prefix = password_hash[:5]
    hash_suffix = password_hash[5:]
    request = Request(
        f"{HIBP_RANGE_API_URL}/{hash_prefix}",
        headers={
            "Add-Padding": "true",
            "User-Agent": "sitbank-password-screening",
        },
    )
    timeout = float(current_app.config.get("HIBP_PASSWORD_CHECK_TIMEOUT_SECONDS", 2.0))

    try:
        with urlopen(request, timeout=timeout) as response:  # nosec B310
            status = getattr(response, "status", 200)
            if status != 200:
                raise LivePasswordCheckUnavailable(f"HIBP returned HTTP {status}")
            payload = response.read(HIBP_MAX_RESPONSE_BYTES + 1)
    except (OSError, TimeoutError, URLError) as exc:
        raise LivePasswordCheckUnavailable("HIBP request failed") from exc

    if len(payload) > HIBP_MAX_RESPONSE_BYTES:
        raise LivePasswordCheckUnavailable("HIBP response exceeded size limit")

    try:
        for line in payload.decode("ascii").splitlines():
            candidate_suffix, separator, count_text = line.partition(":")
            if not separator:
                raise ValueError("Malformed HIBP response line")
            count = int(count_text.strip())
            if hmac.compare_digest(candidate_suffix.strip().upper(), hash_suffix) and count > 0:
                return True
    except (UnicodeDecodeError, ValueError) as exc:
        raise LivePasswordCheckUnavailable("HIBP response could not be parsed") from exc

    return False


def validate_common_password_dictionary() -> int:
    common_passwords = _load_common_passwords(current_app.config["COMMON_PASSWORDS_PATH"])
    return len(common_passwords)


def _hibp_circuit_is_open() -> bool:
    now = _utcnow()
    try:
        breaker = _hibp_breaker()
        if breaker is None or breaker.state != "open" or breaker.opened_until is None:
            return False
        if _as_utc(breaker.opened_until) > now:
            return True
        breaker.state = "closed"
        breaker.failure_count = 0
        breaker.opened_until = None
        breaker.updated_at = now
        db.session.commit()
        return False
    except Exception as exc:
        db.session.rollback()
        current_app.logger.warning("hibp_circuit_state_unavailable error=%s", type(exc).__name__)
        return True


def _record_hibp_failure() -> None:
    now = _utcnow()
    try:
        breaker = _hibp_breaker(lock=True)
        if breaker is None:
            breaker = SecurityCircuitBreaker(
                service_name=HIBP_CIRCUIT_SERVICE,
                state="closed",
                failure_count=0,
                created_at=now,
                updated_at=now,
            )
            db.session.add(breaker)
        breaker.failure_count = int(breaker.failure_count or 0) + 1
        breaker.last_failure_at = now
        breaker.updated_at = now
        threshold = int(current_app.config.get("HIBP_CIRCUIT_FAILURE_THRESHOLD", 3))
        if breaker.failure_count >= threshold:
            breaker.state = "open"
            breaker.opened_until = now + timedelta(seconds=int(current_app.config.get("HIBP_CIRCUIT_OPEN_SECONDS", 300)))
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        current_app.logger.warning("hibp_circuit_failure_record_unavailable error=%s", type(exc).__name__)


def _clear_hibp_failures() -> None:
    now = _utcnow()
    try:
        breaker = _hibp_breaker(lock=True)
        if breaker is None:
            return
        breaker.state = "closed"
        breaker.failure_count = 0
        breaker.opened_until = None
        breaker.last_success_at = now
        breaker.updated_at = now
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        current_app.logger.warning("hibp_circuit_clear_unavailable error=%s", type(exc).__name__)


def _hibp_breaker(*, lock: bool = False) -> SecurityCircuitBreaker | None:
    statement = db.select(SecurityCircuitBreaker).where(
        SecurityCircuitBreaker.service_name == HIBP_CIRCUIT_SERVICE
    )
    if lock and db.engine.dialect.name == "postgresql":
        statement = statement.with_for_update()
    return db.session.execute(statement).scalar_one_or_none()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def hash_password(password: str) -> str:
    iterations = _pbkdf2_iterations()
    salt = os.urandom(PBKDF2_SALT_BYTES)
    digest = _pbkdf2_digest(password, salt, iterations)
    return (
        f"{PBKDF2_PREFIX}${PBKDF2_VERSION}$i={iterations}"
        f"$s={_b64encode(salt)}$h={_b64encode(digest)}"
    )


def verify_password(password: str, password_hash: str) -> bool:
    try:
        if not is_password_raw_length_safe(password):
            return False
        parts = password_hash.split("$")
        if len(parts) != 5 or parts[0] != PBKDF2_PREFIX or parts[1] != PBKDF2_VERSION:
            return False
        iterations = _parse_iterations(parts[2])
        salt = _parse_b64_part(parts[3], "s")
        expected = _parse_b64_part(parts[4], "h")
        candidate = _pbkdf2_digest(password, salt, iterations)
        return hmac.compare_digest(candidate, expected)
    except (AttributeError, TypeError, ValueError, binascii.Error):
        return False


def password_hash_needs_rehash(password_hash: str) -> bool:
    try:
        parts = password_hash.split("$")
        if len(parts) != 5 or parts[0] != PBKDF2_PREFIX or parts[1] != PBKDF2_VERSION:
            return True
        return _parse_iterations(parts[2]) < _pbkdf2_iterations()
    except (AttributeError, TypeError, ValueError):
        return True


def validate_password_hash_config() -> None:
    _password_pepper()
    _pbkdf2_iterations()


def _pbkdf2_digest(password: str, salt: bytes, iterations: int) -> bytes:
    normalized_password = _safe_normalized_password(password)
    peppered = hmac.new(
        _password_pepper(),
        normalized_password.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return hashlib.pbkdf2_hmac(
        "sha256",
        peppered,
        salt,
        iterations,
        dklen=PBKDF2_DERIVED_KEY_BYTES,
    )


def _pbkdf2_iterations() -> int:
    iterations = int(current_app.config.get("PASSWORD_PBKDF2_ITERATIONS", 600_000))
    if iterations < 600_000:
        raise RuntimeError("PASSWORD_PBKDF2_ITERATIONS must be 600000 or higher")
    return iterations


def _password_pepper() -> bytes:
    value = current_app.config.get("PASSWORD_PEPPER_B64")
    if not value:
        raise RuntimeError("PASSWORD_PEPPER_B64 is required")
    try:
        decoded = base64.b64decode(str(value), validate=True)
    except binascii.Error as exc:
        raise RuntimeError("PASSWORD_PEPPER_B64 must be valid base64") from exc
    if len(decoded) != 32:
        raise RuntimeError("PASSWORD_PEPPER_B64 must decode to exactly 32 bytes")
    return decoded


def password_max_chars() -> int:
    configured = int(current_app.config.get("PASSWORD_MAX_CHARS", PASSWORD_MAX_CHARS))
    minimum_length = password_min_length()
    if configured < 64 or configured > 1024:
        raise RuntimeError("PASSWORD_MAX_CHARS must be between 64 and 1024")
    if configured < minimum_length:
        raise RuntimeError("PASSWORD_MAX_CHARS must be at least PASSWORD_MIN_LENGTH")
    return configured


def password_min_length() -> int:
    configured = int(current_app.config.get("PASSWORD_MIN_LENGTH", PASSWORD_MIN_LENGTH))
    if configured < 1 or configured > 1024:
        raise RuntimeError("PASSWORD_MIN_LENGTH must be between 1 and 1024")
    return configured


def is_password_raw_length_safe(password: str) -> bool:
    return isinstance(password, str) and len(password) <= password_max_chars()


def _ensure_raw_password_length(password: str) -> None:
    if not is_password_raw_length_safe(password):
        raise PasswordPolicyError(f"Password must be at most {password_max_chars()} characters")


def _ensure_normalized_password_length(password: str) -> None:
    if len(password) > password_max_chars():
        raise PasswordPolicyError(f"Password must be at most {password_max_chars()} characters")


def _safe_normalized_password(password: str) -> str:
    if not isinstance(password, str):
        raise ValueError("Password is required")
    if len(password) > password_max_chars():
        raise ValueError("Password exceeds maximum length")
    normalized = _normalize_password(password)
    if len(normalized) > password_max_chars():
        raise ValueError("Password exceeds maximum length after normalization")
    return normalized


def _parse_iterations(value: str) -> int:
    label, separator, text = value.partition("=")
    if label != "i" or separator != "=":
        raise ValueError("Invalid PBKDF2 iteration field")
    iterations = int(text)
    if iterations < 600_000:
        raise ValueError("PBKDF2 iteration count is too low")
    return iterations


def _parse_b64_part(value: str, label: str) -> bytes:
    actual_label, separator, text = value.partition("=")
    if actual_label != label or separator != "=":
        raise ValueError("Invalid PBKDF2 field")
    return _b64decode(text)


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    padded = value + ("=" * (-len(value) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _normalize_password(password: str) -> str:
    return unicodedata.normalize("NFC", password)
