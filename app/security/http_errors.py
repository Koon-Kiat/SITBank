from __future__ import annotations

from flask import current_app, jsonify, make_response, render_template, request


JSON_MIME_TYPE = "application/json"
HTML_MIME_TYPE = "text/html"
RATE_LIMIT_MESSAGE = "Too many attempts. Please try again later."
CSRF_ERROR_MESSAGE = "Security token expired or invalid. Please try again."

_ADMIN_JSON_ONLY_ENDPOINTS = frozenset(
    {
        "admin.health_live",
        "admin.health_ready",
        "admin.csrf_token",
    }
)


def request_wants_json() -> bool:
    if request.path.startswith("/auth/") or request.is_json:
        return True
    if (
        current_app.config.get("APP_MODE") == "admin"
        and request.endpoint in _ADMIN_JSON_ONLY_ENDPOINTS
    ):
        return True
    best = request.accept_mimetypes.best_match([JSON_MIME_TYPE, HTML_MIME_TYPE])
    return best == JSON_MIME_TYPE and (
        request.accept_mimetypes[JSON_MIME_TYPE]
        > request.accept_mimetypes[HTML_MIME_TYPE]
    )


def safe_error_response(message: str, status_code: int):
    if request_wants_json():
        return jsonify({"error": message}), status_code
    template = (
        "admin/error.html"
        if current_app.config.get("APP_MODE") == "admin"
        else "error.html"
    )
    return render_template(template, message=message, status_code=status_code), status_code


def rate_limit_response(retry_after: int | None = None):
    response = make_response(safe_error_response(RATE_LIMIT_MESSAGE, 429))
    if retry_after is not None:
        response.headers["Retry-After"] = str(max(1, int(retry_after)))
    return response, 429
