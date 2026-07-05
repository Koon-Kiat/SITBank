from __future__ import annotations

import argparse
import base64
import re
import subprocess
from collections.abc import Iterator
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
    "GitHub fine-grained token": re.compile(rb"\bgithub_pat_\w{40,}\b"),
    "AWS access key": re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "Slack token": re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "Google API key": re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b"),
    "Stripe secret key": re.compile(rb"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b"),
}


def contains_private_key(content: bytes) -> bool:
    for match in PRIVATE_KEY_BLOCK_PATTERN.finditer(content):
        if _private_key_payload_is_substantial(match.group("body")):
            return True
    return False


def _private_key_payload_is_substantial(body: bytes) -> bool:
    encoded_payload = _private_key_payload(body)
    if not re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", encoded_payload):
        return False
    try:
        decoded_payload = base64.b64decode(encoded_payload, validate=True)
    except ValueError:
        return False
    return len(decoded_payload) >= MIN_PRIVATE_KEY_PAYLOAD_BYTES


def _private_key_payload(body: bytes) -> bytes:
    payload_lines: list[bytes] = []
    in_metadata = True
    metadata_seen = False
    normalized_body = body.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    for raw_line in normalized_body.split(b"\n"):
        line = raw_line.strip()
        if not line:
            if metadata_seen:
                in_metadata = False
            continue
        if in_metadata and re.fullmatch(rb"[A-Za-z0-9-]+:.*", line):
            metadata_seen = True
            continue
        in_metadata = False
        payload_lines.append(line)
    return b"".join(payload_lines)


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


def _historical_blob_records() -> list[tuple[str, str, int]]:
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
    candidates: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in result.stdout.splitlines():
        object_id, _, path = line.partition(" ")
        if not path or object_id in seen:
            continue
        seen.add(object_id)
        candidates.append((object_id, path))
    metadata = _batch_object_metadata([object_id for object_id, _path in candidates])
    return [
        (object_id, path, metadata[object_id][1])
        for object_id, path in candidates
        if metadata.get(object_id, ("", 0))[0] == "blob"
    ]


def historical_blobs() -> list[tuple[str, str]]:
    return [
        (object_id, path)
        for object_id, path, _size in _historical_blob_records()
    ]


def _batch_object_metadata(object_ids: list[str]) -> dict[str, tuple[str, int]]:
    if not object_ids:
        return {}
    result = subprocess.run(
        [
            "git",
            "cat-file",
            "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        ],
        input="\n".join(object_ids) + "\n",
        check=True,
        capture_output=True,
        text=True,
    )
    metadata: dict[str, tuple[str, int]] = {}
    for line in result.stdout.splitlines():
        object_id, object_type, raw_size = line.split(" ", 2)
        metadata[object_id] = (object_type, int(raw_size))
    return metadata


def _read_blob_batch(object_ids: list[str]) -> Iterator[tuple[str, bytes]]:
    if not object_ids:
        return
    process = subprocess.Popen(
        ["git", "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise RuntimeError("Git history object scan could not open safe pipes")
    try:
        for expected_object_id in object_ids:
            process.stdin.write(f"{expected_object_id}\n".encode("ascii"))
            process.stdin.flush()
            header = process.stdout.readline().decode("ascii").strip()
            object_id, object_type, raw_size = header.split(" ", 2)
            if object_id != expected_object_id or object_type != "blob":
                raise RuntimeError("Git returned unexpected history object metadata")
            content = process.stdout.read(int(raw_size))
            if process.stdout.read(1) != b"\n":
                raise RuntimeError("Git returned malformed history object content")
            yield object_id, content
        process.stdin.close()
        return_code = process.wait()
        if return_code:
            raise RuntimeError("Git history object scan failed")
    finally:
        if not process.stdin.closed:
            process.stdin.close()
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stderr.close()
        process.stdout.close()


def scan_content(label: str, content: bytes, findings: list[str]) -> None:
    if contains_private_key(content):
        findings.append(f"private key pattern: {label}")
    for pattern_label, pattern in SECRET_PATTERNS.items():
        if pattern.search(content):
            findings.append(f"{pattern_label} pattern: {label}")


def scan_history(findings: list[str]) -> None:
    eligible: list[tuple[str, str]] = []
    for object_id, historical_path, size in _historical_blob_records():
        path = Path(historical_path)
        if (
            path.name.casefold() in FORBIDDEN_NAMES
            or path.suffix.casefold() in FORBIDDEN_SUFFIXES
        ):
            findings.append(
                f"forbidden credential filename in history: {historical_path}"
            )
            continue
        if size > MAX_HISTORY_BLOB_BYTES:
            continue
        eligible.append((object_id, historical_path))
    paths_by_object_id = dict(eligible)
    for object_id, content in _read_blob_batch(
        [object_id for object_id, _path in eligible]
    ):
        historical_path = paths_by_object_id[object_id]
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
