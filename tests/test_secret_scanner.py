from __future__ import annotations

import base64
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from ops.security import scan_repository_secrets as scanner
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


def test_private_key_payload_rejects_invalid_and_short_base64():
    assert scanner._private_key_payload(b"Header: value\n\nYWJj") == b"YWJj"
    assert scanner._private_key_payload_is_substantial(b"%%%") is False
    assert scanner._private_key_payload_is_substantial(base64.b64encode(b"short")) is False


def test_tracked_files_and_historical_blobs_parse_git_output(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if command[:2] == ["git", "ls-files"]:
            return SimpleNamespace(stdout=b"app.py\x00docs/README.md\x00")
        if command[:2] == ["git", "rev-list"]:
            return SimpleNamespace(
                stdout="a" * 40 + " app.py\n" + "b" * 40 + " tree\n" + "a" * 40 + " duplicate.py\n"
            )
        if command[:2] == ["git", "cat-file"]:
            return SimpleNamespace(
                stdout=(
                    ("a" * 40) + " blob 10\n"
                    + ("b" * 40) + " tree 0\n"
                )
            )
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(scanner.subprocess, "run", fake_run)

    assert scanner.tracked_files() == [Path("app.py"), Path("docs/README.md")]
    assert scanner.historical_blobs() == [("a" * 40, "app.py")]
    assert any("--batch-check=" in command[-1] for command in calls)


def test_scan_history_skips_forbidden_and_large_blobs_and_scans_small_content(monkeypatch):
    monkeypatch.setattr(
        scanner,
        "historical_blobs",
        lambda: [
            ("a" * 40, ".env"),
            ("b" * 40, "large.py"),
            ("c" * 40, "small.py"),
        ],
    )
    scanned = []

    monkeypatch.setattr(
        scanner,
        "_batch_object_metadata",
        lambda _object_ids: {
            "a" * 40: ("blob", 10),
            "b" * 40: ("blob", scanner.MAX_HISTORY_BLOB_BYTES + 1),
            "c" * 40: ("blob", 10),
        },
    )
    monkeypatch.setattr(
        scanner,
        "_read_blob_batch",
        lambda object_ids: iter((object_id, b"safe") for object_id in object_ids),
    )
    monkeypatch.setattr(
        scanner,
        "scan_content",
        lambda label, content, findings: scanned.append((label, content)),
    )
    findings = []
    scanner.scan_history(findings)

    assert findings == ["forbidden credential filename in history: .env"]
    assert scanned == [("small.py@" + ("c" * 12), b"safe")]


def test_main_reports_findings_and_supports_history_mode(tmp_path, monkeypatch, capsys):
    safe = tmp_path / "safe.py"
    safe.write_bytes(b"safe")
    forbidden = tmp_path / "id_rsa"
    forbidden.write_bytes(b"fake")
    missing = tmp_path / "missing.py"
    monkeypatch.setattr(scanner, "tracked_files", lambda: [safe, forbidden, missing])
    history_calls = []
    monkeypatch.setattr(
        scanner,
        "scan_history",
        lambda findings: history_calls.append(True),
    )
    monkeypatch.setattr(sys, "argv", ["scan_repository_secrets.py", "--history"])

    with pytest.raises(SystemExit, match="Repository secret scan failed") as exc:
        scanner.main()
    assert "forbidden credential filename" in str(exc.value)
    assert history_calls == [True]

    monkeypatch.setattr(scanner, "tracked_files", lambda: [safe])
    scanner.main()
    assert "Repository secret scan passed" in capsys.readouterr().out
