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

import pyotp
from sqlalchemy.exc import IntegrityError


DAST_COOKIE_RE = re.compile(r"^__Host-sitbank_session=[A-Za-z0-9._~-]+$")


class DastClient:
    def __init__(self, base_url: str, *, allowed_hosts: set[str] | None = None) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        permitted_hosts = {"127.0.0.1", "localhost"} | (allowed_hosts or set())
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
            ("https", parsed.netloc, "/", "", "")
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
            "X-Forwarded-Proto": "https",
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
    password = f"DAST-{secrets.token_urlsafe(24)}-A9!"
    create_dast_user(
        username=username,
        email=email,
        password=password,
        full_name=f"DAST User {suffix}",
        phone_number=_generate_synthetic_phone_number(),
    )

    csrf_token = str(
        client.request(
            "GET",
            "/auth/csrf-token",
            expected_status=200,
        )["csrf_token"]
    )
    client.request(
        "POST",
        "/auth/login",
        payload={"identifier": username, "password": password},
        csrf_token=csrf_token,
        expected_status=200,
    )

    csrf_token = str(
        client.request(
            "GET",
            "/auth/csrf-token",
            expected_status=200,
        )["csrf_token"]
    )
    setup = client.request(
        "POST",
        "/auth/mfa/setup",
        payload={},
        csrf_token=csrf_token,
        expected_status=200,
    )
    code = pyotp.TOTP(str(setup["manual_entry_secret"])).now()
    client.request(
        "POST",
        "/auth/mfa/setup/verify",
        payload={"totp_code": code},
        csrf_token=csrf_token,
        expected_status=200,
    )

    session_cookie = client.cookies.get("__Host-sitbank_session")
    if not session_cookie:
        raise RuntimeError("Authenticated DAST session cookie was not issued")
    return f"__Host-sitbank_session={session_cookie}"


def _generate_synthetic_phone_number() -> str:
    return f"9{secrets.randbelow(9000000) + 1000000}"


def _generate_synthetic_account_number() -> str:
    return "012" + str(secrets.randbelow(1_000_000)).zfill(6)


def create_dast_user(
    *,
    username: str,
    email: str,
    password: str,
    full_name: str,
    phone_number: str,
) -> None:
    from app import create_app
    from app.extensions import db
    from app.models import User
    from app.security.passwords import hash_password

    app = create_app()
    with app.app_context():
        if db.session.execute(db.select(User).where(User.username == username)).scalar_one_or_none():
            return
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
            db.session.add(
                User(
                    username=username,
                    email=email,
                    password_hash=hash_password(password),
                    full_name=full_name,
                    phone_number=candidate_phone,
                    account_number=account_number,
                )
            )
            try:
                db.session.commit()
                return
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
            "replacer.full_list(1).replacement=https",
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
