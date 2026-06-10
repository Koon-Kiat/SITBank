from __future__ import annotations

import re
import subprocess
from pathlib import Path


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
SECRET_PATTERNS = {
    "private key": re.compile(
        rb"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"
    ),
    "GitHub token": re.compile(rb"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b"),
    "GitHub fine-grained token": re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    "AWS access key": re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "Slack token": re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
}


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


def main() -> None:
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
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(content):
                findings.append(f"{label} pattern: {path}")

    if findings:
        raise SystemExit(
            "Repository secret scan failed:\n- " + "\n- ".join(findings)
        )
    print("Repository secret scan passed")


if __name__ == "__main__":
    main()
