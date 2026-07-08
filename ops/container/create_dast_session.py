from __future__ import annotations

import argparse
import http.cookies
import json
import os
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from sqlalchemy.exc import IntegrityError


DAST_COOKIE_RE = re.compile(r"^__Host-sitbank_session=[A-Za-z0-9._~-]+$")
DAST_FORWARDED_FOR = "127.0.0.1"
DAST_FORWARDED_PROTO = "https"
DAST_SMOKE_CONTAINER_HOSTS = frozenset({"sitbank-smoke"})
DAST_SYNTHETIC_USERNAME_RE = re.compile(r"^zap([0-9a-f]{12})$")
DAST_USER_AGENT = "sitbank-dast-session"


class DastClient:
    def __init__(self, base_url: str, *, allowed_hosts: set[str] | None = None) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        requested_hosts = allowed_hosts or set()
        if not requested_hosts.issubset(DAST_SMOKE_CONTAINER_HOSTS):
            raise ValueError("DAST base URL host is not allowed")
        permitted_hosts = {"127.0.0.1", "localhost"} | requested_hosts
        if (
            parsed.scheme != "http"
            or parsed.hostname not in permitted_hosts
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("DAST base URL host is not allowed")
        self.base_url = base_url.rstrip("/")
        self.csrf_referrer = urllib.parse.urlunsplit(
            # The smoke test connects over HTTP but sets X-Forwarded-Proto=https to
            # exercise production proxy behavior. Flask-WTF SSL-strict CSRF checks
            # therefore require a same-origin HTTPS Referer.
            (DAST_FORWARDED_PROTO, parsed.netloc, "/", "", "")
        )
        self.cookies: dict[str, str] = {}

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, str] | None = None,
        csrf_token: str | None = None,
        expected_status: int,
    ) -> dict[str, object]:
        body = None
        headers = {
            "Accept": "application/json",
            "User-Agent": DAST_USER_AGENT,
            "X-Forwarded-For": DAST_FORWARDED_FOR,
            "X-Forwarded-Proto": DAST_FORWARDED_PROTO,
        }
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if csrf_token:
            headers["X-CSRFToken"] = csrf_token
            headers["Referer"] = self.csrf_referrer
        if self.cookies:
            headers["Cookie"] = "; ".join(
                f"{name}={value}" for name, value in self.cookies.items()
            )

        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=body,
            headers=headers,
            method=method,
        )
        try:
            # The constructor restricts requests to the local smoke container.
            response = urllib.request.urlopen(request, timeout=15)  # nosec B310
        except urllib.error.HTTPError as exc:
            response = exc

        self._capture_cookies(response.headers.get_all("Set-Cookie") or [])
        response_body = response.read().decode("utf-8")
        if response.status != expected_status:
            raise RuntimeError(
                f"{method} {path} returned {response.status}: {response_body[:300]}"
            )
        if not response_body:
            return {}
        result = json.loads(response_body)
        if not isinstance(result, dict):
            raise RuntimeError(f"{method} {path} returned a non-object response")
        return result

    def _capture_cookies(self, headers: list[str]) -> None:
        for header in headers:
            parsed = http.cookies.SimpleCookie()
            parsed.load(header)
            for name, morsel in parsed.items():
                self.cookies[name] = morsel.value


def create_authenticated_cookie(
    base_url: str,
    *,
    allowed_hosts: set[str] | None = None,
) -> str:
    client = DastClient(base_url, allowed_hosts=allowed_hosts)
    suffix = secrets.token_hex(6)
    username = f"zap{suffix}"
    email = f"{username}@sit.singaporetech.edu.sg"
    password = f"DAST-{secrets.token_urlsafe(24)}-A9!"  # NOSONAR - ephemeral generated test credential
    user_id = create_dast_user(
        username=username,
        email=email,
        password=password,
        full_name=f"DAST User {suffix}",
        phone_number=_generate_synthetic_phone_number(),
    )

    session_cookie = issue_dast_session_cookie(
        user_id=user_id,
        session_base_url=client.csrf_referrer,
    )
    cookie = f"__Host-sitbank_session={session_cookie}"
    _validate_cookie_header(cookie)
    client.cookies["__Host-sitbank_session"] = session_cookie
    client.request("GET", "/auth/sessions", expected_status=200)
    return cookie


def issue_dast_session_cookie(*, user_id: int, session_base_url: str) -> str:
    from flask import session

    from app import create_app
    from app.extensions import db
    from app.models import User
    from app.security.sessions import establish_authenticated_session

    app = create_app()
    if str(app.config.get("DEPLOYMENT_TARGET") or "").strip().casefold() != "smoke":
        raise RuntimeError("DAST session bootstrap requires the smoke runtime")
    _validate_session_base_url(session_base_url)
    with app.app_context():
        user = db.session.get(User, int(user_id))
        if user is None:
            raise RuntimeError("Synthetic DAST user was not found")
        _validate_synthetic_dast_user(user)
        with app.test_request_context(
            "/",
            base_url=session_base_url,
            environ_base={"REMOTE_ADDR": DAST_FORWARDED_FOR},
            headers={"User-Agent": DAST_USER_AGENT},
        ):
            establish_authenticated_session(
                user_id=user.id,
                mfa_verified=True,
                auth_context="dast_smoke",
            )
            response = app.response_class("")
            app.session_interface.save_session(app, session, response)
        cookie = _cookie_value_from_headers(response.headers.get_all("Set-Cookie"))
    if not cookie:
        raise RuntimeError("Authenticated DAST session cookie was not issued")
    return cookie


def _validate_session_base_url(session_base_url: str) -> None:
    parsed = urllib.parse.urlsplit(session_base_url)
    if (
        parsed.scheme != DAST_FORWARDED_PROTO
        or parsed.hostname
        not in {"127.0.0.1", "localhost", *DAST_SMOKE_CONTAINER_HOSTS}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise RuntimeError("DAST session base URL is not an approved smoke host")


def _validate_synthetic_dast_user(user: object) -> None:
    username = str(getattr(user, "username", ""))
    match = DAST_SYNTHETIC_USERNAME_RE.fullmatch(username)
    suffix = match.group(1) if match else ""
    expected_email = f"{username}@sit.singaporetech.edu.sg"
    expected_name = f"DAST User {suffix}"
    if (
        not match
        or str(getattr(user, "email", "")) != expected_email
        or str(getattr(user, "full_name", "")) != expected_name
        or getattr(user, "account_type", None) != "customer"
        or getattr(user, "account_status", None) != "active"
        or getattr(user, "staff_personal_email", None) is not None
        or getattr(user, "workplace_email_verified_at", None) is not None
        or getattr(user, "registration_email_canonical", None) is not None
        or getattr(user, "mfa_enabled", None) is not True
    ):
        raise RuntimeError("DAST session bootstrap requires a synthetic customer")


def _cookie_value_from_headers(headers: list[str]) -> str:
    for header in headers:
        parsed = http.cookies.SimpleCookie()
        parsed.load(header)
        morsel = parsed.get("__Host-sitbank_session")
        if morsel is not None:
            return morsel.value
    return ""


def _generate_synthetic_phone_number() -> str:
    return f"9{secrets.randbelow(9000000) + 1000000}"


def _generate_synthetic_account_number() -> str:
    return str(secrets.randbelow(1_000_000_000_000)).zfill(12)


def create_dast_user(
    *,
    username: str,
    email: str,
    password: str,
    full_name: str,
    phone_number: str,
) -> int:
    from app import create_app
    from app.extensions import db
    from app.models import User
    from app.security.passwords import hash_password

    app = create_app()
    with app.app_context():
        existing = db.session.execute(db.select(User).where(User.username == username)).scalar_one_or_none()
        if existing:
            raise RuntimeError("Synthetic DAST username collision")
        for attempt in range(20):
            candidate_phone = phone_number if attempt == 0 else _generate_synthetic_phone_number()
            if db.session.execute(db.select(User).where(User.phone_number == candidate_phone)).scalar_one_or_none():
                continue
            account_number = None
            for _account_attempt in range(20):
                candidate_account = _generate_synthetic_account_number()
                if not db.session.execute(
                    db.select(User).where(User.account_number == candidate_account)
                ).scalar_one_or_none():
                    account_number = candidate_account
                    break
            if account_number is None:
                continue
            user = User(
                username=username,
                email=email,
                password_hash=hash_password(password),
                full_name=full_name,
                phone_number=candidate_phone,
                account_number=account_number,
                mfa_enabled=True,
            )
            db.session.add(user)
            try:
                db.session.commit()
                return int(user.id)
            except IntegrityError:
                db.session.rollback()
        raise RuntimeError("Could not create a unique synthetic DAST user")


def write_cookie_output(path: Path, cookie: str, *, allowed_root: Path) -> None:
    _validate_cookie_header(cookie)
    _write_secret_file(path, cookie, allowed_root=allowed_root)


def write_zap_replacer_config(path: Path, cookie: str, *, allowed_root: Path) -> None:
    _validate_cookie_header(cookie)
    config = "\n".join(
        (
            "replacer.full_list(0).description=authenticated-session",
            "replacer.full_list(0).enabled=true",
            "replacer.full_list(0).matchtype=REQ_HEADER",
            "replacer.full_list(0).matchstr=Cookie",
            f"replacer.full_list(0).replacement={cookie}",
            "replacer.full_list(1).description=trusted-https-proxy",
            "replacer.full_list(1).enabled=true",
            "replacer.full_list(1).matchtype=REQ_HEADER",
            "replacer.full_list(1).matchstr=X-Forwarded-Proto",
            f"replacer.full_list(1).replacement={DAST_FORWARDED_PROTO}",
            "replacer.full_list(2).description=trusted-forwarded-for",
            "replacer.full_list(2).enabled=true",
            "replacer.full_list(2).matchtype=REQ_HEADER",
            "replacer.full_list(2).matchstr=X-Forwarded-For",
            f"replacer.full_list(2).replacement={DAST_FORWARDED_FOR}",
            "replacer.full_list(3).description=dast-session-user-agent",
            "replacer.full_list(3).enabled=true",
            "replacer.full_list(3).matchtype=REQ_HEADER",
            "replacer.full_list(3).matchstr=User-Agent",
            f"replacer.full_list(3).replacement={DAST_USER_AGENT}",
        )
    )
    _write_secret_file(path, f"{config}\n", allowed_root=allowed_root)


def _validate_cookie_header(cookie: str) -> None:
    if not DAST_COOKIE_RE.fullmatch(cookie):
        raise RuntimeError("Authenticated DAST session cookie is malformed")


def _validated_output_path(path: Path, allowed_root: Path) -> Path:
    root = allowed_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("DAST output root must be a directory")
    parent = path.parent.resolve(strict=True)
    candidate = parent / path.name
    if candidate == root or not candidate.is_relative_to(root):
        raise ValueError("DAST output path escapes the allowed output root")
    return candidate


def _write_secret_file(path: Path, contents: str, *, allowed_root: Path) -> None:
    path = _validated_output_path(path, allowed_root)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    previous_umask = os.umask(0o077)
    try:
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(contents)
        path.chmod(0o600)
    finally:
        os.umask(previous_umask)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:5000")
    parser.add_argument(
        "--allow-host",
        action="append",
        default=[],
        help="additional exact HTTP host allowed for Docker-network smoke tests",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--zap-replacer-config-output", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()

    cookie = create_authenticated_cookie(
        args.base_url,
        allowed_hosts=set(args.allow_host),
    )
    write_cookie_output(args.output, cookie, allowed_root=args.output_root)
    write_zap_replacer_config(
        args.zap_replacer_config_output,
        cookie,
        allowed_root=args.output_root,
    )


if __name__ == "__main__":
    main()
