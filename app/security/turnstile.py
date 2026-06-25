from __future__ import annotations

import json
from urllib import parse, request as urlrequest

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
    verifier = urlrequest.Request(
        str(current_app.config["TURNSTILE_VERIFY_URL"]),
        data=payload,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urlrequest.urlopen(verifier, timeout=5) as response:
            body = response.read(16 * 1024)
        result = json.loads(body.decode("utf-8"))
    except Exception as exc:
        raise TurnstileError("Challenge verification failed") from exc
    if not isinstance(result, dict) or result.get("success") is not True:
        raise TurnstileError("Challenge verification failed")
