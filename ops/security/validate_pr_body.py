from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path


REQUIRED_SECTIONS = (
    "Summary",
    "Why",
    "What changed",
    "Security impact",
    "Deployment impact",
    "Verification",
    "Notes",
)

PLACEHOLDERS = (
    "Briefly describe what this PR improves or fixes.",
    "Explain the problem, risk, or reason this change is needed.",
    "Explain how this affects security controls, secrets, permissions, auth, CI/CD, deployment safety, or runtime behavior.",
    "Explain whether this PR requires:",
    "Add any follow-up work, limitations, or operator instructions.",
)

DEPLOYMENT_IMPACT_PATTERNS = (
    r"\bec2 bootstrap\b",
    r"\bstaging deployment\b",
    r"\bproduction deployment\b",
    r"\bdatabase migration\b",
    r"\bsecret changes?\b",
    r"\bno deployment action\b",
    r"\bno deployment action required\b",
    r"\bno deployment required\b",
)

HEADING_RE = re.compile(
    r"^\s{0,3}(?:#{1,6}\s*)?"
    r"(summary|why|what changed|security impact|deployment impact|verification|notes)"
    r"\s*:?\s*$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ValidationError:
    message: str
    value: str


def annotation_escape(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def load_body_from_event(path: Path) -> str:
    payload = json.loads(path.read_text(encoding="utf-8"))
    body = (payload.get("pull_request") or {}).get("body") or ""
    return str(body)


def parse_sections(body: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in body.splitlines():
        heading = HEADING_RE.match(line)
        if heading:
            current = _canonical_section_name(heading.group(1))
            sections.setdefault(current, [])
            continue
        if current is not None:
            sections[current].append(line)
    return {name: "\n".join(lines).strip() for name, lines in sections.items()}


def validate_body(body: str) -> list[ValidationError]:
    errors: list[ValidationError] = []
    if not body.strip():
        return [ValidationError("PR description must not be empty.", body)]

    for placeholder in PLACEHOLDERS:
        if placeholder in body:
            errors.append(
                ValidationError(
                    "PR description still contains unchanged template placeholder text.",
                    placeholder,
                )
            )

    sections = parse_sections(body)
    for section in REQUIRED_SECTIONS:
        if section not in sections:
            errors.append(ValidationError(f"Missing required PR description section: {section}.", body[:240]))
            continue
        if section != "Notes" and not _has_meaningful_content(sections[section]):
            errors.append(
                ValidationError(
                    f"PR description section '{section}' must contain meaningful content.",
                    sections[section],
                )
            )

    deployment_impact = sections.get("Deployment impact", "")
    if "Deployment impact" in sections and not _has_deployment_impact(deployment_impact):
        errors.append(
            ValidationError(
                "Deployment impact must state at least one concrete deployment impact.",
                deployment_impact,
            )
        )

    verification = sections.get("Verification", "")
    if "Verification" in sections and not _has_meaningful_content(verification):
        errors.append(
            ValidationError(
                "Verification must include at least one test command, manual check, CI check, or explanation.",
                verification,
            )
        )

    return errors


def print_examples() -> None:
    print(
        """Valid PR description example:
Summary
Adds server-side Payee management required for Local Transfer.

Why
Local Transfer needs trusted recipient records before transfer creation.

What changed
* Added Payee model and routes
* Added server-side validation
* Added tests for invalid recipient input

Security impact
Recipient names are loaded from the database and are not accepted from client input.

Deployment impact
No deployment action required.

Verification
* python -m pytest tests/test_payees.py

Notes
No follow-up required.
""".rstrip()
    )


def report_errors(errors: list[ValidationError]) -> None:
    for error in errors:
        print(
            "::error title=Invalid PR description::"
            f"{error.message} Value: {annotation_escape(error.value[:500])}"
        )
    print_examples()


def _canonical_section_name(name: str) -> str:
    lowered = " ".join(name.casefold().split())
    return {section.casefold(): section for section in REQUIRED_SECTIONS}[lowered]


def _has_deployment_impact(content: str) -> bool:
    normalized = _normalize_text(content)
    return any(re.search(pattern, normalized, flags=re.IGNORECASE) for pattern in DEPLOYMENT_IMPACT_PATTERNS)


def _has_meaningful_content(content: str) -> bool:
    for line in content.splitlines():
        normalized = _normalize_line(line)
        if not normalized:
            continue
        if normalized in {"*", "-", "n/a", "na", "none"}:
            continue
        if any(normalized == placeholder.casefold() for placeholder in PLACEHOLDERS):
            continue
        return True
    return False


def _normalize_line(line: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"^\s*[*-]\s*", "", line).strip()).casefold()


def _normalize_text(content: str) -> str:
    return re.sub(r"\s+", " ", content.strip()).casefold()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a GitHub pull request description.")
    parser.add_argument("--event-path", type=Path, help="Path to a GitHub pull_request event JSON payload.")
    parser.add_argument("--body-file", type=Path, help="Path to a text file containing a PR body.")
    args = parser.parse_args(argv)

    if args.body_file:
        body = args.body_file.read_text(encoding="utf-8")
    elif args.event_path:
        body = load_body_from_event(args.event_path)
    else:
        parser.error("Provide --event-path or --body-file.")

    errors = validate_body(body)
    if errors:
        report_errors(errors)
        return 1
    print("PR description policy passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
