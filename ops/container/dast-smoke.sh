#!/usr/bin/env bash
set -Eeuo pipefail

readonly IMAGE="${1:-sitbank:smoke}"
readonly POSTGRES_IMAGE="postgres:16.9-alpine@sha256:7c688148e5e156d0e86df7ba8ae5a05a2386aaec1e2ad8e6d11bdf10504b1fb7"
readonly REDIS_IMAGE="redis:7.4.5-alpine@sha256:bb186d083732f669da90be8b0f975a37812b15e913465bb14d845db72a4e3e08"
readonly PUBLIC_HOST="sitbank.duckdns.org"

work_dir="$(mktemp -d)"
chmod 2770 "${work_dir}"

# shellcheck disable=SC2317
cleanup() {
    docker rm -f sitbank-dast dast-postgres dast-redis >/dev/null 2>&1 || true
    rm -rf -- "${work_dir}"
}
trap cleanup EXIT

runner_gid="$(id -g)"
docker run --detach --name dast-postgres \
    --group-add "${runner_gid}" \
    --publish 127.0.0.1:55433:5432 \
    --env POSTGRES_USER=ci \
    --env POSTGRES_PASSWORD=ci-password \
    --env POSTGRES_DB=ci \
    "${POSTGRES_IMAGE}" >/dev/null
docker run --detach --name dast-redis \
    --group-add "${runner_gid}" \
    --publish 127.0.0.1:56380:6379 \
    "${REDIS_IMAGE}" \
    redis-server --requirepass ci-password >/dev/null

for _ in $(seq 1 30); do
    if docker exec dast-postgres pg_isready --username ci --dbname ci >/dev/null 2>&1 \
        && docker exec dast-redis redis-cli -a ci-password ping 2>/dev/null \
            | grep -q PONG; then
        break
    fi
    sleep 1
done
docker exec dast-postgres pg_isready --username ci --dbname ci >/dev/null
docker exec dast-redis redis-cli -a ci-password ping 2>/dev/null | grep -q PONG

install -d -m 0770 "${work_dir}/secrets" "${work_dir}/config"
printf '%s' 'ci-secret-key-that-is-long-enough-for-dast-tests' \
    > "${work_dir}/secrets/secret_key"
printf '%s' 'ci-csrf-key-that-is-long-enough-for-dast-tests' \
    > "${work_dir}/secrets/wtf_csrf_secret_key"
printf '%s' '{"ci":"MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjI="}' \
    > "${work_dir}/secrets/session_hmac_keys_json"
printf '%s' 'postgresql+psycopg2://ci:ci-password@127.0.0.1:55433/ci' \
    > "${work_dir}/secrets/database_url"
printf '%s' 'redis://:ci-password@127.0.0.1:56380/15' \
    > "${work_dir}/secrets/redis_url"
printf '%s' '{"ci-mfa":"NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ="}' \
    > "${work_dir}/secrets/mfa_kek_keys_json"
printf '%s' 'MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=' \
    > "${work_dir}/secrets/password_pepper_b64"
printf '%s' 'ci-audit-hmac-key-that-is-long-enough-for-dast-tests' \
    > "${work_dir}/secrets/security_audit_hmac_key"
chmod 0444 "${work_dir}"/secrets/*

seq -f 'blocked-password-%06g' 1 100000 \
    > "${work_dir}/config/common-passwords.txt"
cp tests/fixtures/fido-approved-aaguids.json \
    "${work_dir}/config/fido-approved-aaguids.json"
cp tests/fixtures/fido-mds-cache.json \
    "${work_dir}/config/fido-mds-cache.json"
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
    --env DATABASE_URL_FILE=/run/secrets/database_url
    --env REDIS_URL_FILE=/run/secrets/redis_url
    --env MFA_KEK_ACTIVE_ID=ci-mfa
    --env MFA_KEK_KEYS_JSON_FILE=/run/secrets/mfa_kek_keys_json
    --env PASSWORD_PEPPER_B64_FILE=/run/secrets/password_pepper_b64
    --env SECURITY_AUDIT_HMAC_KEY_FILE=/run/secrets/security_audit_hmac_key
    --env SECURITY_AUDIT_ANCHOR_PATH=/run/state/security-audit.anchor
    --env PASSWORD_PBKDF2_ITERATIONS=600000
    --env COMMON_PASSWORDS_PATH=/run/config/common-passwords.txt
    --env COMMON_PASSWORDS_MIN_ENTRIES=100000
    --env WEBAUTHN_RP_ID="${PUBLIC_HOST}"
    --env WEBAUTHN_RP_ORIGIN="https://${PUBLIC_HOST}"
    --env WEBAUTHN_APPROVED_AAGUIDS_PATH=/run/config/fido-approved-aaguids.json
    --env WEBAUTHN_MDS_CACHE_PATH=/run/config/fido-mds-cache.json
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
