from __future__ import annotations

import base64

from ops.security.scan_repository_secrets import scan_content, scan_history


def _private_key_block(label: bytes, body: bytes) -> bytes:
    return (
        b"-----BEGIN "
        + label
        + b"-----\n"
        + body
        + b"\n-----END "
        + label
        + b"-----\n"
    )


def test_secret_scanner_detects_complete_private_key_payload():
    encoded_payload = base64.b64encode(b"private-key-payload" * 8)
    findings: list[str] = []

    scan_content(
        "fixture",
        _private_key_block(b"OPENSSH PRIVATE KEY", encoded_payload),
        findings,
    )

    assert findings == ["private key pattern: fixture"]


def test_secret_scanner_detects_legacy_encrypted_pem_metadata():
    encoded_payload = base64.b64encode(b"encrypted-private-key-payload" * 6)
    body = (
        b"Proc-Type: 4,ENCRYPTED\n"
        b"DEK-Info: AES-256-CBC,0123456789ABCDEF\n\n"
        + encoded_payload
    )
    findings: list[str] = []

    scan_content(
        "legacy-encrypted-fixture",
        _private_key_block(b"RSA PRIVATE KEY", body),
        findings,
    )

    assert findings == ["private key pattern: legacy-encrypted-fixture"]


def test_secret_scanner_ignores_documented_header_and_placeholder():
    findings: list[str] = []
    documented_header = b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----"
    placeholder = _private_key_block(b"OPENSSH PRIVATE KEY", b"...")

    scan_content("documentation", documented_header + b"\n" + placeholder, findings)

    assert findings == []


def test_repository_history_contains_no_complete_private_key():
    findings: list[str] = []

    scan_history(findings)

    assert not [
        finding
        for finding in findings
        if finding.startswith("private key pattern:")
    ]
