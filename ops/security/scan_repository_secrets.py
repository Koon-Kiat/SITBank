from __future__ import annotations

import argparse
import base64
import binascii
import re
import subprocess
from pathlib import Path


MAX_HISTORY_BLOB_BYTES = 5 * 1024 * 1024
FORBIDDEN_NAMES = {
    ".env",
    "id_ed25519",
    "id_rsa",
}
FORBIDDEN_SUFFIXES = {
    ".jks",
    ".key",
    ".keystore",
    ".p12",
    ".pfx",
    ".ppk",
}
PRIVATE_KEY_BLOCK_PATTERN = re.compile(
    rb"-----BEGIN "
    rb"(?P<label>(?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY)"
    rb"-----(?P<body>.*?)-----END (?P=label)-----",
    re.DOTALL,
)
MIN_PRIVATE_KEY_PAYLOAD_BYTES = 48

SECRET_PATTERNS = {
    "GitHub token": re.compile(rb"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b"),
    "GitHub fine-grained token": re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    "AWS access key": re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "Slack token": re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "Google API key": re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b"),
    "Stripe secret key": re.compile(rb"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b"),
}


def contains_private_key(content: bytes) -> bool:
    for match in PRIVATE_KEY_BLOCK_PATTERN.finditer(content):
        encoded_payload = re.sub(rb"\s+", b"", match.group("body"))
        if not re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", encoded_payload):
            continue
        try:
            decoded_payload = base64.b64decode(encoded_payload, validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(decoded_payload) >= MIN_PRIVATE_KEY_PAYLOAD_BYTES:
            return True
    return False


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        check=True,
        capture_output=True,
    )
    return [
        Path(raw_path.decode("utf-8"))
        for raw_path in result.stdout.split(b"\x00")
        if raw_path
    ]


def historical_blobs() -> list[tuple[str, str]]:
    result = subprocess.run(
        [
            "git",
            "rev-list",
            "--objects",
            "HEAD",
            "--branches",
            "--tags",
            "--remotes",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    blobs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in result.stdout.splitlines():
        object_id, _, path = line.partition(" ")
        if not path or object_id in seen:
            continue
        object_type = subprocess.run(
            ["git", "cat-file", "-t", object_id],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if object_type != "blob":
            continue
        seen.add(object_id)
        blobs.append((object_id, path))
    return blobs


def scan_content(label: str, content: bytes, findings: list[str]) -> None:
    if contains_private_key(content):
        findings.append(f"private key pattern: {label}")
    for pattern_label, pattern in SECRET_PATTERNS.items():
        if pattern.search(content):
            findings.append(f"{pattern_label} pattern: {label}")


def scan_history(findings: list[str]) -> None:
    for object_id, historical_path in historical_blobs():
        path = Path(historical_path)
        if (
            path.name.casefold() in FORBIDDEN_NAMES
            or path.suffix.casefold() in FORBIDDEN_SUFFIXES
        ):
            findings.append(
                f"forbidden credential filename in history: {historical_path}"
            )
            continue
        size = int(
            subprocess.run(
                ["git", "cat-file", "-s", object_id],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        )
        if size > MAX_HISTORY_BLOB_BYTES:
            continue
        content = subprocess.run(
            ["git", "cat-file", "blob", object_id],
            check=True,
            capture_output=True,
        ).stdout
        scan_content(f"{historical_path}@{object_id[:12]}", content, findings)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--history",
        action="store_true",
        help="also scan every reachable Git blob",
    )
    args = parser.parse_args()

    findings: list[str] = []
    for path in tracked_files():
        if not path.exists():
            continue
        normalized_name = path.name.casefold()
        if normalized_name in FORBIDDEN_NAMES or path.suffix.casefold() in FORBIDDEN_SUFFIXES:
            findings.append(f"forbidden credential filename: {path}")
            continue
        try:
            content = path.read_bytes()
        except OSError as exc:
            findings.append(f"could not scan {path}: {exc}")
            continue
        scan_content(str(path), content, findings)

    if args.history:
        scan_history(findings)

    if findings:
        raise SystemExit(
            "Repository secret scan failed:\n- " + "\n- ".join(findings)
        )
    print("Repository secret scan passed")


if __name__ == "__main__":
    main()
