from __future__ import annotations

import argparse
import fnmatch
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


MAX_AUTO_LABELS = 6
ISSUE_DEFAULT_LABEL = "needs-triage"

LABEL_DEFINITIONS: dict[str, tuple[str, str]] = {
    "needs-triage": ("New issue awaiting maintainer triage.", "fbca04"),
    "needs-review": ("Ready for maintainer review.", "0e8a16"),
    "security": ("Security behavior, secure configuration, auditability, or secure SDLC evidence.", "d73a4a"),
    "admin": ("Admin application, routes, sessions, private boundary, or admin-only operations.", "b60205"),
    "customer": ("Customer application, routes, accounts, or customer-facing behavior.", "1d76db"),
    "banking": ("Accounts, transfers, payees, balances, freezes, funds, or transaction safety.", "0052cc"),
    "auth": ("Login, registration, credential handling, identity proofing, or authentication policy.", "c5def5"),
    "mfa": ("TOTP, passkeys, WebAuthn, recovery codes, step-up, or MFA lifecycle.", "5319e7"),
    "session": ("Cookies, server sessions, CSRF-linked state, rotation, revocation, or session HMAC.", "0b7285"),
    "audit": ("Audit logs, hash chains, metadata, alerting, or audit events.", "d93f0b"),
    "deployment": ("Deployment workflows, containers, EC2, Nginx, systemd, bootstrap, or release gates.", "006b75"),
    "zero-trust": ("Cloudflare Access, Tailscale, identity-aware access, or private access boundaries.", "5319e7"),
    "network-security": ("TLS, Nginx edge controls, origin protection, VPN, or network boundaries.", "d73a4a"),
    "staging": ("Staging environment, hostname, deployment, or staging access controls.", "006b75"),
    "database": ("Schema, migrations, database roles, permissions, retention, or database access.", "531dab"),
    "ci": ("GitHub Actions, CI policy, scanners, dependency review, build, or pipeline changes.", "a2eeef"),
    "code-quality": ("Static analysis, maintainability, coverage, or quality-gate work.", "1f6feb"),
    "dependencies": ("Dependency updates, lock files, package managers, or Dependabot.", "0366d6"),
    "documentation": ("Documentation, README, guides, instructions, or policy documents.", "0075ca"),
    "frontend": ("Templates, CSS, JavaScript, SVG, UI layout, or browser-facing pages.", "c2e0c6"),
    "tests": ("Tests, pytest, fixtures, coverage, or regression checks.", "fef2c0"),
    "feature": ("Feature branch or feature-oriented change.", "84b6eb"),
    "fix": ("Fix, bugfix, or hotfix branch.", "d4c5f9"),
    "docker": ("Dockerfile, image, Compose, or Docker dependency updates.", "0db7ed"),
    "github-actions": ("GitHub Actions workflow dependency updates or CI automation.", "2088ff"),
    "python": ("Python source, dependency, or runtime changes.", "3572a5"),
}


@dataclass(frozen=True)
class LabelRule:
    label: str
    terms: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()
    branches: tuple[str, ...] = ()


RULES: tuple[LabelRule, ...] = (
    LabelRule(
        "security",
        (
            "security",
            "vulnerability",
            "secure configuration",
            "authorization bypass",
            "authentication bypass",
            "privilege escalation",
            "secret scanning",
            "gitleaks",
            "codeql",
            "semgrep",
            "harden",
        ),
        (
            "app/security/**",
            "ops/security/**",
            "docs/security/**",
            "SECURITY.md",
            ".github/workflows/codeql.yml",
            ".github/workflows/gitleaks.yml",
            ".github/workflows/semgrep.yml",
        ),
        ("security", "hardening"),
    ),
    LabelRule(
        "auth",
        (
            "authentication",
            "login",
            "registration",
            "password reset",
            "credential handling",
            "identity proofing",
            "auth policy",
        ),
        ("app/auth/**", "tests/test_auth_*.py", "tests/test_password*.py"),
        ("auth", "login", "password"),
    ),
    LabelRule(
        "session",
        (
            "server session",
            "session cookie",
            "session rotation",
            "session revocation",
            "session hmac",
            "session-bound",
            "csrf session",
        ),
        (
            "app/security/sessions.py",
            "app/security/session_hmac.py",
            "tests/test_session_*.py",
        ),
        ("session",),
    ),
    LabelRule(
        "mfa",
        ("mfa", "totp", "webauthn", "passkey", "recovery code", "step-up", "second factor"),
        (
            "app/auth/mfa_policy.py",
            "app/auth/recovery_codes.py",
            "app/auth/webauthn_services.py",
            "tests/test_mfa_*.py",
            "tests/test_webauthn_*.py",
        ),
        ("mfa", "totp", "webauthn", "passkey"),
    ),
    LabelRule(
        "admin",
        (
            "admin app",
            "admin route",
            "admin session",
            "admin deployment",
            "root-admin",
            "admin-only",
            "private admin",
        ),
        ("app/admin/**", "admin_wsgi.py", "tests/test_admin_*.py"),
        ("admin",),
    ),
    LabelRule(
        "customer",
        ("customer app", "customer route", "customer account", "customer portal"),
        ("app/main/**", "app/banking/**", "tests/test_dashboard.py"),
        ("customer",),
    ),
    LabelRule(
        "database",
        ("database", "postgres", "schema", "migration", "database role", "database permission", "audit table"),
        ("migrations/**", "app/models.py", "app/ops/db_privileges.py", "ops/postgres/**"),
        ("database", "migration", "postgres"),
    ),
    LabelRule(
        "deployment",
        (
            "deployment workflow",
            "deploy",
            "container",
            "ec2",
            "nginx",
            "systemd",
            "bootstrap",
            "release gate",
        ),
        (
            "ops/deploy/**",
            "ops/nginx/**",
            "compose*.yml",
            "Dockerfile",
            ".github/workflows/ci-deploy.yml",
            ".github/workflows/tls-scan.yml",
        ),
        ("deploy", "deployment", "release"),
    ),
    LabelRule(
        "network-security",
        (
            "cloudflare",
            "tls",
            "origin protection",
            "authenticated origin pull",
            "tailscale",
            "vpn",
            "private access",
            "network boundary",
            "security header",
        ),
        ("ops/nginx/**", "ops/cloudflare/**", "ops/tailscale/**"),
        ("cloudflare", "tailscale", "network-security"),
    ),
    LabelRule(
        "zero-trust",
        (
            "cloudflare access",
            "tailscale",
            "identity-aware access",
            "zero trust",
            "zero-trust",
            "private admin boundary",
            "staging access boundary",
        ),
        ("ops/cloudflare/**", "ops/tailscale/**", "docs/security/**/*zero-trust*"),
        ("zero-trust", "cloudflare", "tailscale"),
    ),
    LabelRule(
        "staging",
        ("staging environment", "staging hostname", "staging deployment", "staging access", "staging control"),
        ("compose.staging.yml", "ops/cloudflare/**", "ops/**/*staging*", "tests/**/*staging*.py"),
        ("staging",),
    ),
    LabelRule(
        "dependencies",
        ("dependency", "dependencies", "dependabot", "lockfile", "lock file", "package update", "bump "),
        (
            "requirements*.in",
            "requirements*.lock",
            ".github/dependabot.yml",
            "ops/security/check_dependency_locks.py",
        ),
        ("dependabot", "dependencies"),
    ),
    LabelRule(
        "ci",
        (
            "github actions",
            "workflow",
            "continuous integration",
            "dependency review",
            "dependency-review",
            "codeql",
            "semgrep",
            "sonarqube",
            "quality gate",
        ),
        (".github/workflows/**", "scripts/ci-local"),
        ("ci", "github-actions"),
    ),
    LabelRule(
        "code-quality",
        ("sonarqube", "sonarcloud", "static analysis", "quality gate", "code quality", "maintainability", "coverage"),
        (
            "sonar-project.properties",
            ".github/workflows/sonarqube.yml",
            ".github/workflows/codeql.yml",
            ".github/workflows/semgrep.yml",
            "tests/test_sonarqube_*.py",
        ),
        ("sonar", "code-quality", "coverage"),
    ),
    LabelRule(
        "documentation",
        ("documentation", "document", "docs", "readme", "runbook", "guide"),
        ("docs/**", "README*", "SECURITY.md", "AGENTS.md"),
        ("docs", "documentation"),
    ),
    LabelRule(
        "tests",
        ("test coverage", "tests", "pytest", "regression test", "test suite"),
        ("tests/**", "pytest.ini"),
        ("tests",),
    ),
    LabelRule(
        "frontend",
        ("frontend", "template", "css", "javascript", "browser ui", "user interface"),
        ("app/templates/**", "app/static/**", "**/*.css", "**/*.js", "**/*.svg"),
        ("frontend", "ui"),
    ),
    LabelRule(
        "python",
        ("python", "flask"),
        ("app/**/*.py", "ops/**/*.py", "tests/**/*.py", "requirements*.in", "requirements*.lock"),
        ("python",),
    ),
    LabelRule(
        "banking",
        ("transfer", "payee", "account balance", "freeze account", "banking"),
        ("app/banking/**", "tests/test_banking_*.py", "tests/test_local_transfer*.py"),
        ("banking", "transfer"),
    ),
)


_FOCUSED_HEADINGS = {
    "summary",
    "required implementation",
    "what changed",
    "why",
    "root cause",
}


def _normalized(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").casefold()).strip()


def _focused_body(body: str) -> str:
    sections: list[str] = []
    current_heading = ""
    current_lines: list[str] = []

    def append_current() -> None:
        if not current_heading or current_heading in _FOCUSED_HEADINGS:
            sections.extend(current_lines)

    for line in str(body or "").splitlines():
        heading = re.match(r"^#{1,6}\s+(.+?)\s*$", line)
        if heading:
            append_current()
            current_heading = _normalized(heading.group(1))
            current_lines = []
            continue
        current_lines.append(line)
    append_current()
    return _normalized("\n".join(sections))


def _matches_path(path: str, pattern: str) -> bool:
    normalized_path = path.replace("\\", "/")
    return fnmatch.fnmatchcase(normalized_path, pattern)


def _term_score(text: str, terms: Iterable[str], weight: int) -> int:
    return sum(weight for term in terms if _normalized(term) in text)


def _rule_score(
    rule: LabelRule,
    *,
    title: str,
    focused_body: str,
    head: str,
    paths: Sequence[str],
) -> int:
    score = min(_term_score(title, rule.terms, 4), 8)
    score += min(_term_score(focused_body, rule.terms, 1), 3)
    score += min(_term_score(head, rule.branches, 4), 4)
    if any(_matches_path(path, pattern) for path in paths for pattern in rule.paths):
        score += 5
    return score


def compute_labels(
    *,
    kind: str,
    title: str,
    body: str = "",
    head: str = "",
    paths: Sequence[str] = (),
) -> list[str]:
    if kind not in {"issue", "pr"}:
        raise ValueError("kind must be 'issue' or 'pr'")

    normalized_title = _normalized(title)
    normalized_head = _normalized(head)
    focused_body = _focused_body(body)
    scored = [
        (score, index, rule.label)
        for index, rule in enumerate(RULES)
        if (score := _rule_score(
            rule,
            title=normalized_title,
            focused_body=focused_body,
            head=normalized_head,
            paths=paths,
        ))
        >= 4
    ]
    labels = [label for _, _, label in sorted(scored, key=lambda item: (-item[0], item[1]))]
    labels = labels[:MAX_AUTO_LABELS]
    if kind == "issue":
        return [ISSUE_DEFAULT_LABEL, *labels]
    return labels


def _load_input(path: str) -> dict[str, Any]:
    if path == "-":
        import sys

        value = json.load(sys.stdin)
    else:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("label input must be a JSON object")
    return value


def _event_item(data: dict[str, Any], kind: str) -> dict[str, Any]:
    key = "issue" if kind == "issue" else "pull_request"
    item = data.get(key, data)
    if not isinstance(item, dict):
        raise ValueError(f"{key} label input must be a JSON object")
    return item


def _command_compute(args: argparse.Namespace) -> int:
    data = _load_input(args.input)
    item = _event_item(data, args.kind)
    paths = item.get("paths", data.get("paths", []))
    if not isinstance(paths, list) or not all(isinstance(path, str) for path in paths):
        raise ValueError("paths must be a list of strings")
    labels = compute_labels(
        kind=args.kind,
        title=str(item.get("title", "")),
        body=str(item.get("body", "") or ""),
        head=str(item.get("head", item.get("headRefName", "")) or ""),
        paths=paths,
    )
    print("\n".join(labels))
    return 0


def _command_definitions() -> int:
    for label, (description, color) in LABEL_DEFINITIONS.items():
        print(f"{label}\t{description}\t{color}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compute bounded SITBank GitHub labels.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    compute = subparsers.add_parser("compute")
    compute.add_argument("--kind", choices=("issue", "pr"), required=True)
    compute.add_argument("--input", default="-")
    compute.set_defaults(handler=_command_compute)

    definitions = subparsers.add_parser("definitions")
    definitions.set_defaults(handler=lambda _args: _command_definitions())
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
