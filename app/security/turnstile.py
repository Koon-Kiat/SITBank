from __future__ import annotations

import json
import http.client
from urllib import parse

from flask import current_app, request


class TurnstileError(ValueError):
    pass


def verify_turnstile_token(token: str | None) -> None:
    if not current_app.config.get("TURNSTILE_ENABLED", False):
        return
    token_text = str(token or "").strip()
    secret_key = str(current_app.config.get("TURNSTILE_SECRET_KEY") or "").strip()
    if not token_text or not secret_key:
        raise TurnstileError("Challenge verification failed")

    payload = parse.urlencode(
        {
            "secret": secret_key,
            "response": token_text,
            "remoteip": request.remote_addr or "",
        }
    ).encode("utf-8")
    try:
        host, port, target = _turnstile_verify_target()
        connection = http.client.HTTPSConnection(host, port=port, timeout=5)
        try:
            connection.request(
                "POST",
                target,
                body=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response = connection.getresponse()
            body = response.read(16 * 1024)
        finally:
            connection.close()
        result = json.loads(body.decode("utf-8"))
    except Exception as exc:
        raise TurnstileError("Challenge verification failed") from exc
    if not isinstance(result, dict) or result.get("success") is not True:
        raise TurnstileError("Challenge verification failed")


def _turnstile_verify_target() -> tuple[str, int | None, str]:
    raw_url = str(current_app.config["TURNSTILE_VERIFY_URL"])
    parsed = parse.urlsplit(raw_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise TurnstileError("Challenge verification failed")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise TurnstileError("Challenge verification failed")
    path = parsed.path or "/"
    return parsed.hostname, parsed.port, path
