#!/usr/bin/env bash
set -Eeuo pipefail

readonly IMAGE="${1:-sitbank:smoke}"
readonly POSTGRES_IMAGE="postgres:16.9-alpine@sha256:7c688148e5e156d0e86df7ba8ae5a05a2386aaec1e2ad8e6d11bdf10504b1fb7"
readonly ZAP_IMAGE="zaproxy/zap-stable:2.17.0@sha256:2ec1d5d5b44d55cfd02ba9b89cd26852f06d92b7fc0ce9f064b9463babc73074"
readonly PUBLIC_HOST="sitbank.pp.ua"
readonly root_admin_emails="chief1@sit.singaporetech.edu.sg,chief2@sit.singaporetech.edu.sg,chief3@sit.singaporetech.edu.sg,chief4@sit.singaporetech.edu.sg,chief5@sit.singaporetech.edu.sg,chief6@sit.singaporetech.edu.sg,chief7@sit.singaporetech.edu.sg"

random_test_secret() {
    od -An -N24 -tx1 /dev/urandom | tr -d '[:space:]'
}

postgres_password="$(random_test_secret)"
readonly postgres_password

work_dir="$(mktemp -d)"
chmod 2770 "${work_dir}"

# Invoked through the EXIT trap registered below; ShellCheck cannot trace it.
# shellcheck disable=SC2317
cleanup() {
    docker rm -f sitbank-dast dast-postgres >/dev/null 2>&1 || true
    rm -rf -- "${work_dir}"
}
trap cleanup EXIT

runner_gid="$(id -g)"
docker run --detach --name dast-postgres \
    --group-add "${runner_gid}" \
    --publish 127.0.0.1:55433:5432 \
    --env POSTGRES_USER=ci \
    --env POSTGRES_PASSWORD="${postgres_password}" \
    --env POSTGRES_DB=ci \
    "${POSTGRES_IMAGE}" >/dev/null

for _ in $(seq 1 30); do
    if docker exec dast-postgres pg_isready --username ci --dbname ci >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
docker exec dast-postgres pg_isready --username ci --dbname ci >/dev/null

install -d -m 0770 "${work_dir}/secrets" "${work_dir}/config"
printf '%s' 'ci-secret-key-that-is-long-enough-for-dast-tests' \
    > "${work_dir}/secrets/secret_key"
printf '%s' 'ci-csrf-key-that-is-long-enough-for-dast-tests' \
    > "${work_dir}/secrets/wtf_csrf_secret_key"
printf '%s' '{"ci":"MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjI="}' \
    > "${work_dir}/secrets/session_hmac_keys_json"
printf '%s' 'OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk=' \
    > "${work_dir}/secrets/session_lookup_hmac_key"
printf 'postgresql+psycopg2://ci:%s@127.0.0.1:55433/ci' "${postgres_password}" \
    > "${work_dir}/secrets/database_url"
printf '%s' '{"ci-mfa":"NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ="}' \
    > "${work_dir}/secrets/mfa_kek_keys_json"
printf '%s' 'MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=' \
    > "${work_dir}/secrets/password_pepper_b64"
printf '%s' 'ci-audit-hmac-key-that-is-long-enough-for-dast-tests' \
    > "${work_dir}/secrets/security_audit_hmac_key"
printf '%s' 'https://hooks.example.test/sitbank-security-alerts' \
    > "${work_dir}/secrets/security_alert_webhook_url"
printf '%s' 'smtp-user' \
    > "${work_dir}/secrets/smtp_username"
printf '%s' 'smtp-password' \
    > "${work_dir}/secrets/smtp_password"
printf '%s' "${root_admin_emails}" \
    > "${work_dir}/secrets/root_admin_emails"
chmod 0444 "${work_dir}"/secrets/*

seq -f 'blocked-password-%06g' 1 100000 \
    > "${work_dir}/config/common-passwords.txt"
chmod 0444 "${work_dir}"/config/*

docker_args=(
    --network host
    --user 10001:10001
    --group-add "${runner_gid}"
    --read-only
    --tmpfs "/tmp:rw,noexec,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=1770"
    --tmpfs "/run/state:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0750"
    --cap-drop ALL
    --security-opt no-new-privileges:true
    --env APP_ENV=production
    --env SECRET_KEY_FILE=/run/secrets/secret_key
    --env WTF_CSRF_SECRET_KEY_FILE=/run/secrets/wtf_csrf_secret_key
    --env SESSION_HMAC_ACTIVE_KEY_ID=ci
    --env SESSION_HMAC_KEYS_JSON_FILE=/run/secrets/session_hmac_keys_json
    --env SESSION_LOOKUP_HMAC_KEY_FILE=/run/secrets/session_lookup_hmac_key
    --env DATABASE_URL_FILE=/run/secrets/database_url
    --env MFA_KEK_ACTIVE_ID=ci-mfa
    --env MFA_KEK_KEYS_JSON_FILE=/run/secrets/mfa_kek_keys_json
    --env PASSWORD_PEPPER_B64_FILE=/run/secrets/password_pepper_b64
    --env SECURITY_AUDIT_HMAC_KEY_FILE=/run/secrets/security_audit_hmac_key
    --env SECURITY_AUDIT_ANCHOR_PATH=/run/state/security-audit.anchor
    --env SECURITY_ALERT_WEBHOOK_URL_FILE=/run/secrets/security_alert_webhook_url
    --env PAYEE_COOLDOWN_SECONDS=43200
    --env PASSWORD_PBKDF2_ITERATIONS=600000
    --env PASSWORD_RESET_ENABLED=true
    --env PASSWORD_RESET_TOKEN_TTL_SECONDS=1800
    --env PASSWORD_RESET_TRANSACTION_TTL_SECONDS=900
    --env PASSWORD_RESET_EMAIL_BACKEND=smtp
    --env PASSWORD_RESET_EMAIL_FROM=security@sitbank.example
    --env "PASSWORD_RESET_BASE_URL=https://${PUBLIC_HOST}"
    --env ROOT_ADMIN_EMAILS_FILE=/run/secrets/root_admin_emails
    --env SMTP_HOST=smtp.example.test
    --env SMTP_PORT=587
    --env SMTP_USE_TLS=true
    --env SMTP_USERNAME_FILE=/run/secrets/smtp_username
    --env SMTP_PASSWORD_FILE=/run/secrets/smtp_password
    --env COMMON_PASSWORDS_PATH=/run/config/common-passwords.txt
    --env COMMON_PASSWORDS_MIN_ENTRIES=100000
    --env TRUSTED_PROXY_COUNT=1
    --volume "${work_dir}/secrets:/run/secrets:ro"
    --volume "${work_dir}/config:/run/config:ro"
)

docker run --rm "${docker_args[@]}" "${IMAGE}" \
    python -m flask --app wsgi:app db upgrade
docker run --detach --name sitbank-dast \
    "${docker_args[@]}" "${IMAGE}" >/dev/null
for _ in $(seq 1 20); do
    if curl --fail --silent \
        --header "Host: ${PUBLIC_HOST}" \
        --header "X-Forwarded-Proto: https" \
        http://127.0.0.1:5000/health/ready >/dev/null; then
        break
    fi
    sleep 1
done
curl --fail --silent \
    --header "Host: ${PUBLIC_HOST}" \
    --header "X-Forwarded-Proto: https" \
    http://127.0.0.1:5000/health/ready >/dev/null

if [[ "${RUN_ZAP_BASELINE:-false}" == "true" ]]; then
    zap_dir="${work_dir}/zap-pr"
    install -d -m 0777 "${zap_dir}"
    printf '10020\tFAIL\n10021\tFAIL\n10038\tFAIL\n' \
        > "${zap_dir}/rules.tsv"
    chmod 0644 "${zap_dir}/rules.tsv"
    docker run --rm \
        --network host \
        --volume "${zap_dir}:/zap/wrk:rw" \
        "${ZAP_IMAGE}" \
        zap-baseline.py \
        -t http://127.0.0.1:5000/ \
        -m 2 \
        -T 5 \
        -I \
        -c /zap/wrk/rules.tsv \
        -z "-config replacer.full_list(0).description=ForwardedProto \
-config replacer.full_list(0).enabled=true \
-config replacer.full_list(0).matchtype=REQ_HEADER \
-config replacer.full_list(0).matchstr=X-Forwarded-Proto \
-config replacer.full_list(0).replacement=https \
-config replacer.full_list(1).description=Host \
-config replacer.full_list(1).enabled=true \
-config replacer.full_list(1).matchtype=REQ_HEADER \
-config replacer.full_list(1).matchstr=Host \
-config replacer.full_list(1).replacement=${PUBLIC_HOST}"
fi

cookie_jar="${work_dir}/dast.cookies"
: > "${cookie_jar}"
chmod 0640 "${cookie_jar}"

python - "${cookie_jar}" "${PUBLIC_HOST}" <<'PY'
from __future__ import annotations

import http.cookies
import json
import os
import sys
import urllib.error
import urllib.request


cookie_path = sys.argv[1]
public_host = sys.argv[2]
base_url = "http://127.0.0.1:5000"
cookies: dict[str, str] = {}


def update_cookies(headers) -> None:
    for raw_cookie in headers.get_all("Set-Cookie", []):
        parsed = http.cookies.SimpleCookie()
        parsed.load(raw_cookie)
        for name, morsel in parsed.items():
            cookies[name] = morsel.value
        if "__Host-sitbank_session" in raw_cookie:
            lowered = raw_cookie.casefold()
            required = ("secure", "httponly", "samesite=strict")
            missing = [flag for flag in required if flag not in lowered]
            if missing:
                raise RuntimeError(f"Session cookie is missing flags: {', '.join(missing)}")


def save_cookie_names() -> None:
    with open(cookie_path, "w", encoding="utf-8", newline="\n") as handle:
        for name in sorted(cookies):
            handle.write(f"{name}\n")
    os.chmod(cookie_path, 0o640)


def request_json(path: str, payload: dict | None = None, csrf: str | None = None):
    headers = {
        "Accept": "application/json",
        "Host": public_host,
        "User-Agent": "sitbank-dast-smoke",
        "X-Forwarded-Host": public_host,
        "X-Forwarded-Proto": "https",
    }
    if cookies:
        headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in cookies.items())
    body = None
    method = "GET"
    if payload is not None:
        method = "POST"
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
        headers["Referer"] = f"https://{public_host}{path}"
    if csrf is not None:
        headers["X-CSRFToken"] = csrf
    req = urllib.request.Request(
        f"{base_url}{path}",
        data=body,
        headers=headers,
        method=method,
    )
    try:
        response = urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as exc:
        response = exc
    update_cookies(response.headers)
    save_cookie_names()
    return response


def read_json(response):
    payload = response.read().decode("utf-8")
    return json.loads(payload)


index = request_json("/")
csp = index.headers.get("Content-Security-Policy", "")
if index.status != 200:
    raise RuntimeError(f"Unexpected index status: {index.status}")
if "default-src 'self'" not in csp or "script-src 'self'" not in csp:
    raise RuntimeError("CSP header is missing required self directives")
if index.headers.get("X-Frame-Options", "").casefold() != "sameorigin":
    raise RuntimeError("Frame restriction header is missing")

csrf = read_json(request_json("/auth/csrf-token"))["csrf_token"]
register = request_json(
    "/auth/register",
    {
        "username": "dastuser",
        "email": "dast@example.test",
        "password": "correct horse battery staple 2026",
        "confirm_password": "correct horse battery staple 2026",
    },
    csrf,
)
if register.status != 201:
    raise RuntimeError(f"Unexpected register status: {register.status}")

csrf = read_json(request_json("/auth/csrf-token"))["csrf_token"]
login = request_json(
    "/auth/login",
    {"identifier": "dastuser", "password": "correct horse battery staple 2026"},
    csrf,
)
login_payload = read_json(login)
if login.status != 200 or not login_payload.get("mfa_setup_required"):
    raise RuntimeError("Login did not create an authenticated MFA setup session")

mfa_setup = request_json("/mfa/setup")
page = mfa_setup.read().decode("utf-8", errors="replace")
if mfa_setup.status != 200 or "Authenticator MFA" not in page:
    raise RuntimeError("Authenticated MFA setup page was not reachable")
if mfa_setup.headers.get("Cache-Control", "").casefold().find("no-store") < 0:
    raise RuntimeError("Authenticated page is missing no-store cache control")
PY
