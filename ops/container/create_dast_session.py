from __future__ import annotations

import argparse
import http.cookies
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pyotp


class DastClient:
    def __init__(self, base_url: str) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost"}
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("DAST base URL must be loopback HTTP")
        self.base_url = base_url.rstrip("/")
        self.csrf_referrer = urllib.parse.urlunsplit(
            # The smoke test connects over loopback HTTP but sets X-Forwarded-Proto=https
            # to exercise production proxy behavior. Flask-WTF SSL-strict CSRF checks
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


def create_authenticated_cookie(base_url: str) -> str:
    client = DastClient(base_url)
    suffix = secrets.token_hex(6)
    username = f"zap{suffix}"
    password = f"DAST-{secrets.token_urlsafe(24)}-A9!"

    csrf_token = str(
        client.request(
            "GET",
            "/auth/csrf-token",
            expected_status=200,
        )["csrf_token"]
    )
    client.request(
        "POST",
        "/auth/register",
         payload={
             "username": username,
             "email": f"{username}@example.test",
             "password": password,
             "confirm_password": password,
         },
        csrf_token=csrf_token,
        expected_status=201,
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:5000")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    cookie = create_authenticated_cookie(args.base_url)
    args.output.write_text(cookie, encoding="utf-8", newline="")
    args.output.chmod(0o644)


if __name__ == "__main__":
    main()
