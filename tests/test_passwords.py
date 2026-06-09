from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

from flask import Flask

from app.security.passwords import (
    HIBP_UNAVAILABLE_ERROR,
    PASSWORD_MAX_CHARS,
    PBKDF2_PREFIX,
    PasswordPolicyError,
    hash_password,
    validate_password_policy,
    verify_password,
)


class FakeResponse:
    def __init__(self, payload: bytes, status: int = 200) -> None:
        self.payload = payload
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def read(self, _size: int) -> bytes:
        return self.payload


class PasswordPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
        handle.write("known-local-password\n")
        handle.close()
        self.password_file = Path(handle.name)

        self.app = Flask(__name__)
        self.app.config.update(
            COMMON_PASSWORDS_PATH=str(self.password_file),
            COMMON_PASSWORDS_MIN_ENTRIES=1,
            HIBP_PASSWORD_CHECK_TIMEOUT_SECONDS=0.25,
            PASSWORD_PEPPER_B64="MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=",
            PASSWORD_PBKDF2_ITERATIONS=600000,
        )
        self.context = self.app.app_context()
        self.context.push()

    def tearDown(self) -> None:
        self.context.pop()
        self.password_file.unlink()

    @patch("app.security.passwords.urlopen")
    def test_rejects_password_found_in_local_blocklist_without_remote_call(self, urlopen) -> None:
        with self.assertRaises(PasswordPolicyError):
            validate_password_policy("known-local-password")

        urlopen.assert_not_called()

    @patch("app.security.passwords.urlopen")
    def test_rejects_password_found_by_hibp_range_api(self, urlopen) -> None:
        password = "breached-remotely-only"
        suffix = hashlib.sha1(
            password.encode("utf-8"),
            usedforsecurity=False,
        ).hexdigest().upper()[5:]
        urlopen.return_value = FakeResponse(f"{suffix}:42\r\n".encode("ascii"))

        with self.assertRaises(PasswordPolicyError):
            validate_password_policy(password)

    @patch("app.security.passwords.urlopen")
    def test_rejects_registration_when_hibp_is_unavailable(self, urlopen) -> None:
        urlopen.side_effect = URLError("offline")

        with self.assertRaisesRegex(PasswordPolicyError, HIBP_UNAVAILABLE_ERROR):
            validate_password_policy("not-in-local-list")

    @patch("app.security.passwords._normalize_password")
    def test_rejects_oversized_password_before_normalization(self, normalize_password) -> None:
        normalize_password.side_effect = AssertionError("normalization should not run")

        with self.assertRaisesRegex(PasswordPolicyError, "at most"):
            validate_password_policy("A" * 300)

    def test_rejects_300_character_password_directly(self) -> None:
        with self.assertRaisesRegex(PasswordPolicyError, "at most 256 characters"):
            validate_password_policy("A" * 300)

    @patch("app.security.passwords.urlopen")
    def test_allows_256_character_password_length(self, urlopen) -> None:
        urlopen.return_value = FakeResponse(b"00000000000000000000000000000000000:0\r\n")

        self.assertEqual(validate_password_policy("A" * PASSWORD_MAX_CHARS), [])

    @patch("app.security.passwords.urlopen")
    def test_sends_only_hash_prefix_with_padding_and_short_timeout(self, urlopen) -> None:
        password = "not-in-local-list"
        password_hash = hashlib.sha1(
            password.encode("utf-8"),
            usedforsecurity=False,
        ).hexdigest().upper()
        urlopen.return_value = FakeResponse(b"00000000000000000000000000000000000:0\r\n")

        self.assertEqual(validate_password_policy(password), [])

        request = urlopen.call_args.args[0]
        self.assertTrue(request.full_url.endswith(f"/{password_hash[:5]}"))
        self.assertNotIn(password, request.full_url)
        self.assertEqual(request.headers["Add-padding"], "true")
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 0.25)

    @patch("app.security.passwords.urlopen")
    def test_allows_long_ascii_and_unicode_passwords(self, urlopen) -> None:
        urlopen.return_value = FakeResponse(b"00000000000000000000000000000000000:0\r\n")

        long_ascii_password = "correct horse battery staple " * 8
        long_unicode_password = "correct horse battery staple " + ("\u5b89\u5168\u306a\u5408\u8a00\u8449" * 12)

        self.assertEqual(validate_password_policy(long_ascii_password), [])
        self.assertEqual(validate_password_policy(long_unicode_password), [])

    def test_hashes_long_unicode_passwords_with_pbkdf2_and_rejects_legacy_hashes(self) -> None:
        password = "correct horse battery staple " + ("\u5b89\u5168\u306a\u5408\u8a00\u8449" * 12)
        password_hash = hash_password(password)
        legacy_bcrypt_hash = "$2b$12$w7W16l.k2YRrSu7rlXG9GeKl2FpA1/b6jqve8GXCYgQFPu74B3k2."

        self.assertTrue(password_hash.startswith(f"{PBKDF2_PREFIX}$v1$i=600000$"))
        self.assertTrue(verify_password(password, password_hash))
        self.assertFalse(verify_password("legacy direct bcrypt", legacy_bcrypt_hash))
        self.assertFalse(verify_password(password + "!", password_hash))

    def test_password_hashing_normalizes_unicode_with_nfc(self) -> None:
        decomposed_password = "correct horse " + ("e\u0301" * 8)
        composed_password = "correct horse " + ("\u00e9" * 8)

        password_hash = hash_password(decomposed_password)

        self.assertTrue(verify_password(composed_password, password_hash))


if __name__ == "__main__":
    unittest.main()
