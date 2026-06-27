#!/usr/bin/env bash
set -Eeuo pipefail

readonly IMAGE="${1:-sitbank:smoke}"
readonly POSTGRES_IMAGE="postgres:16.9-alpine@sha256:7c688148e5e156d0e86df7ba8ae5a05a2386aaec1e2ad8e6d11bdf10504b1fb7"
readonly ZAP_IMAGE="zaproxy/zap-stable:2.17.0@sha256:2ec1d5d5b44d55cfd02ba9b89cd26852f06d92b7fc0ce9f064b9463babc73074"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work_dir="$(mktemp -d)"
network_name="sitbank-smoke-$RANDOM-$$"
readonly postgres_container="smoke-postgres"
readonly app_container="sitbank-smoke"
readonly admin_container="sitbank-admin-smoke"

docker_bind_source() {
    local path="$1"
    case "$(uname -s)" in
        MINGW* | MSYS* | CYGWIN*)
            cygpath -w "${path}"
            ;;
        *)
            printf '%s' "${path}"
            ;;
    esac
}

dump_container_diagnostics() {
    local container
    for container in "${postgres_container}" "${app_container}" "${admin_container}"; do
        if ! docker inspect "${container}" >/dev/null 2>&1; then
            continue
        fi
        echo "::group::${container} status and logs"
        docker inspect --format \
            'status={{.State.Status}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} exit={{.State.ExitCode}} error={{.State.Error}}' \
            "${container}" || true
        docker inspect --format \
            '{{if .State.Health}}{{range .State.Health.Log}}health_exit={{.ExitCode}} output={{printf "%q" .Output}}{{println}}{{end}}{{end}}' \
            "${container}" || true
        docker logs "${container}" || true
        echo "::endgroup::"
    done
}

on_error() {
    local exit_code=$?
    echo "::error::Container smoke test failed with exit code ${exit_code}"
    dump_container_diagnostics
    exit "${exit_code}"
}

wait_for_healthy() {
    local container="$1"
    local status
    for _ in $(seq 1 60); do
        status="$(
            docker inspect --format \
                '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
                "${container}" 2>/dev/null || true
        )"
        case "${status}" in
            healthy)
                return 0
                ;;
            exited | dead | unhealthy)
                echo "${container} entered unexpected state: ${status}" >&2
                return 1
                ;;
        esac
        sleep 1
    done
    echo "${container} did not become healthy within 60 seconds" >&2
    return 1
}

published_port() {
    local container="$1"
    local container_port="$2"
    local mapping
    mapping="$(docker port "${container}" "${container_port}/tcp")"
    if [[ "${mapping}" != 127.0.0.1:* ]]; then
        echo "Unexpected loopback port mapping for ${container}: ${mapping}" >&2
        return 1
    fi
    printf '%s' "${mapping##*:}"
}

# shellcheck disable=SC2317
cleanup() {
    docker rm -f "${app_container}" "${admin_container}" "${postgres_container}" >/dev/null 2>&1 || true
    docker network rm "${network_name}" >/dev/null 2>&1 || true
    rm -rf -- "${work_dir}"
}
trap cleanup EXIT
trap on_error ERR

docker network create "${network_name}" >/dev/null
docker run --detach --name "${postgres_container}" \
    --network "${network_name}" \
    --env POSTGRES_USER=postgres \
    --env POSTGRES_PASSWORD=ci-postgres-password \
    --env POSTGRES_DB=ci \
    --health-cmd "pg_isready --username postgres --dbname ci" \
    --health-interval 1s \
    --health-timeout 3s \
    --health-start-period 2s \
    --health-retries 30 \
    "${POSTGRES_IMAGE}" >/dev/null

wait_for_healthy "${postgres_container}"

psql_admin() {
    docker exec -i -e PGPASSWORD=ci-postgres-password "${postgres_container}" \
        psql --no-psqlrc --set ON_ERROR_STOP=1 \
        --username postgres --dbname ci "$@"
}

psql_admin --set owner_password=ci-owner-password <<'SQL'
CREATE ROLE ci_owner LOGIN PASSWORD :'owner_password';
SQL

psql_admin --set app_password=ci-app-password <<'SQL'
CREATE ROLE ci_app LOGIN PASSWORD :'app_password';
SQL

psql_admin --set admin_password=ci-admin-password <<'SQL'
CREATE ROLE ci_admin LOGIN PASSWORD :'admin_password';
SQL

psql_admin <<'SQL'
REVOKE ALL ON DATABASE ci FROM PUBLIC;
GRANT CONNECT ON DATABASE ci TO ci_owner, ci_app, ci_admin;
ALTER DATABASE ci OWNER TO ci_owner;
SQL

psql_admin <<'SQL'
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM ci_app;
ALTER SCHEMA public OWNER TO ci_owner;
GRANT USAGE ON SCHEMA public TO ci_app, ci_admin;
ALTER DEFAULT PRIVILEGES FOR ROLE ci_owner IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ci_app;
ALTER DEFAULT PRIVILEGES FOR ROLE ci_owner IN SCHEMA public
    GRANT SELECT, INSERT ON TABLES TO ci_admin;
ALTER DEFAULT PRIVILEGES FOR ROLE ci_owner IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO ci_app;
ALTER DEFAULT PRIVILEGES FOR ROLE ci_owner IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO ci_admin;
SQL

roles="$(
    docker exec -e PGPASSWORD=ci-postgres-password "${postgres_container}" \
        psql --no-psqlrc --set ON_ERROR_STOP=1 \
        --username postgres --dbname ci \
        --tuples-only --no-align \
        --command "SELECT rolname FROM pg_roles WHERE rolname IN ('ci_owner', 'ci_app', 'ci_admin') ORDER BY rolname;"
)"
if ! grep -qx "ci_admin" <<<"${roles}"; then
    echo "Admin role exists: no"
    echo "Admin role was not created in the smoke database" >&2
    exit 1
fi
echo "Admin role exists: yes"
if ! grep -qx "ci_owner" <<<"${roles}"; then
    echo "Owner role exists: no"
    echo "Owner role was not created in the smoke database" >&2
    exit 1
fi
echo "Owner role exists: yes"
if ! grep -qx "ci_app" <<<"${roles}"; then
    echo "Runtime role exists: no"
    echo "Runtime role was not created in the smoke database" >&2
    exit 1
fi
echo "Runtime role exists: yes"
owner_database="$(
    docker run --rm --network "${network_name}" \
        --env PGPASSWORD=ci-owner-password \
        "${POSTGRES_IMAGE}" \
        psql --no-psqlrc --set ON_ERROR_STOP=1 \
        --host "${postgres_container}" --username ci_owner --dbname ci \
        --tuples-only --no-align \
        --command "SELECT current_database();"
)"
if [[ "${owner_database}" != "ci" ]]; then
    echo "Owner connection test: failed" >&2
    exit 1
fi
echo "Owner connection test: passed"
runtime_database="$(
    docker run --rm --network "${network_name}" \
        --env PGPASSWORD=ci-app-password \
        "${POSTGRES_IMAGE}" \
        psql --no-psqlrc --set ON_ERROR_STOP=1 \
        --host "${postgres_container}" --username ci_app --dbname ci \
        --tuples-only --no-align \
        --command "SELECT current_database();"
)"
if [[ "${runtime_database}" != "${owner_database}" ]]; then
    echo "Runtime connection test: failed" >&2
    exit 1
fi
runtime_user="$(
    docker run --rm --network "${network_name}" \
        --env PGPASSWORD=ci-app-password \
        "${POSTGRES_IMAGE}" \
        psql --no-psqlrc --set ON_ERROR_STOP=1 \
        --host "${postgres_container}" --username ci_app --dbname ci \
        --tuples-only --no-align \
        --command "SELECT current_user;"
)"
if [[ "${runtime_user}" != "ci_app" ]]; then
    echo "Runtime connection test: failed" >&2
    echo "Runtime smoke database connection did not use ci_app" >&2
    exit 1
fi
echo "Runtime connection test: passed"
admin_user="$(
    docker run --rm --network "${network_name}" \
        --env PGPASSWORD=ci-admin-password \
        "${POSTGRES_IMAGE}" \
        psql --no-psqlrc --set ON_ERROR_STOP=1 \
        --host "${postgres_container}" --username ci_admin --dbname ci \
        --tuples-only --no-align \
        --command "SELECT current_user;"
)"
if [[ "${admin_user}" != "ci_admin" ]]; then
    echo "Admin connection test: failed" >&2
    echo "Admin smoke database connection did not use ci_admin" >&2
    exit 1
fi
echo "Admin connection test: passed"
echo "Postgres smoke DB host: ${postgres_container}"

install -d -m 0755 "${work_dir}/secrets" "${work_dir}/config"
printf '%s' 'ci-secret-key-that-is-long-enough-for-container-tests' \
    > "${work_dir}/secrets/secret_key"
printf '%s' 'ci-csrf-key-that-is-long-enough-for-container-tests' \
    > "${work_dir}/secrets/wtf_csrf_secret_key"
printf '%s' '{"ci":"MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjI="}' \
    > "${work_dir}/secrets/session_hmac_keys_json"
printf '%s' 'OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk=' \
    > "${work_dir}/secrets/session_lookup_hmac_key"
printf 'postgresql+psycopg2://ci_app:ci-app-password@%s:5432/ci' \
    "${postgres_container}" \
    > "${work_dir}/secrets/database_url"
printf 'postgresql+psycopg2://ci_owner:ci-owner-password@%s:5432/ci' \
    "${postgres_container}" \
    > "${work_dir}/secrets/database_migration_url"
printf '%s' '{"ci-mfa":"NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ="}' \
    > "${work_dir}/secrets/mfa_kek_keys_json"
printf '%s' 'MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=' \
    > "${work_dir}/secrets/password_pepper_b64"
printf '%s' 'ci-audit-hmac-key-that-is-long-enough-for-container-tests' \
    > "${work_dir}/secrets/security_audit_hmac_key"
printf '%s' 'https://hooks.example.test/sitbank-security-alerts' \
    > "${work_dir}/secrets/security_alert_webhook_url"
printf '%s' 'ci-admin-secret-key-that-is-long-enough-for-container-tests' \
    > "${work_dir}/secrets/admin_secret_key"
printf '%s' 'ci-admin-csrf-key-that-is-long-enough-for-container-tests' \
    > "${work_dir}/secrets/admin_wtf_csrf_secret_key"
printf '%s' '{"ci-admin":"NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY="}' \
    > "${work_dir}/secrets/admin_session_hmac_keys_json"
printf '%s' 'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=' \
    > "${work_dir}/secrets/admin_session_lookup_hmac_key"
printf 'postgresql+psycopg2://ci_admin:ci-admin-password@%s:5432/ci' \
    "${postgres_container}" \
    > "${work_dir}/secrets/admin_database_url"
printf '%s' 'ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg=' \
    > "${work_dir}/secrets/admin_password_pepper_b64"
printf '%s' 'smtp-user' \
    > "${work_dir}/secrets/smtp_username"
printf '%s' 'smtp-password' \
    > "${work_dir}/secrets/smtp_password"
chmod 0444 "${work_dir}"/secrets/*

seq -f 'blocked-password-%06g' 1 100000 \
    > "${work_dir}/config/common-passwords.txt"
chmod 0444 "${work_dir}"/config/*

secrets_mount_source="$(docker_bind_source "${work_dir}/secrets")"
config_mount_source="$(docker_bind_source "${work_dir}/config")"
create_dast_session_source="$(docker_bind_source "${repo_root}/ops/container/create_dast_session.py")"

docker_args=(
    --network "${network_name}"
    --user 10001:10001
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
    --env PAYEE_COOLDOWN_SECONDS=43200
    --env PASSWORD_PEPPER_B64_FILE=/run/secrets/password_pepper_b64
    --env SECURITY_AUDIT_HMAC_KEY_FILE=/run/secrets/security_audit_hmac_key
    --env SECURITY_AUDIT_ANCHOR_PATH=/run/state/security-audit.anchor
    --env SECURITY_ALERT_WEBHOOK_URL_FILE=/run/secrets/security_alert_webhook_url
    --env ADMIN_SECRET_KEY_FILE=/run/secrets/admin_secret_key
    --env ADMIN_WTF_CSRF_SECRET_KEY_FILE=/run/secrets/admin_wtf_csrf_secret_key
    --env ADMIN_SESSION_HMAC_ACTIVE_KEY_ID=ci-admin
    --env ADMIN_SESSION_HMAC_KEYS_JSON_FILE=/run/secrets/admin_session_hmac_keys_json
    --env ADMIN_SESSION_LOOKUP_HMAC_KEY_FILE=/run/secrets/admin_session_lookup_hmac_key
    --env ADMIN_DATABASE_URL_FILE=/run/secrets/admin_database_url
    --env ADMIN_PASSWORD_PEPPER_B64_FILE=/run/secrets/admin_password_pepper_b64
    --env ADMIN_SESSION_KEY_PREFIX=admin-session:
    --env ADMIN_RATELIMIT_KEY_PREFIX=ospbank:admin:ratelimit:
    --env SMTP_USERNAME_FILE=/run/secrets/smtp_username
    --env SMTP_PASSWORD_FILE=/run/secrets/smtp_password
    --env PASSWORD_PBKDF2_ITERATIONS=600000
    --env PASSWORD_RESET_ENABLED=true
    --env PASSWORD_RESET_TOKEN_TTL_SECONDS=1800
    --env PASSWORD_RESET_TRANSACTION_TTL_SECONDS=900
    --env PASSWORD_RESET_EMAIL_BACKEND=smtp
    --env PASSWORD_RESET_EMAIL_FROM=security@sitbank.example
    --env PASSWORD_RESET_BASE_URL=https://sitbank.duckdns.org
    --env SMTP_HOST=smtp.example.test
    --env SMTP_PORT=587
    --env SMTP_USE_TLS=true
    --env COMMON_PASSWORDS_PATH=/run/config/common-passwords.txt
    --env COMMON_PASSWORDS_MIN_ENTRIES=100000
    --env TRUSTED_PROXY_COUNT=1
    --volume "${secrets_mount_source}:/run/secrets:ro"
    --volume "${config_mount_source}:/run/config:ro"
)
app_command=(
    python -m gunicorn
    --workers 3
    --bind 0.0.0.0:5000
    --access-logfile -
    --error-logfile -
    --timeout 30
    --graceful-timeout 30
    wsgi:app
)
admin_command=(
    python -m gunicorn
    --workers 2
    --bind 0.0.0.0:5002
    --access-logfile -
    --error-logfile -
    --timeout 30
    --graceful-timeout 30
    admin_wsgi:app
)
migration_docker_args=(
    "${docker_args[@]}"
    --env DATABASE_MIGRATION_URL_FILE=/run/secrets/database_migration_url
)

wait_for_app_from_smoke_network() {
    local base_url="$1"
    docker run --rm "${docker_args[@]}" "${IMAGE}" python - "${base_url}" <<'PY'
import sys
import time
import urllib.request

base_url = sys.argv[1].rstrip("/")
request = urllib.request.Request(
    f"{base_url}/health/ready",
    headers={"X-Forwarded-Proto": "https"},
)
for _ in range(60):
    try:
        with urllib.request.urlopen(request, timeout=4) as response:  # nosec B310
            if response.status == 200:
                sys.exit(0)
    except OSError:
        time.sleep(1)
sys.exit(1)
PY
}

docker run --rm "${migration_docker_args[@]}" "${IMAGE}" \
    python -m flask --app wsgi:app db upgrade
docker run --rm "${migration_docker_args[@]}" "${IMAGE}" \
    python -m flask --app wsgi:app apply-runtime-db-privileges
docker run --rm "${docker_args[@]}" "${IMAGE}" \
    python -m flask --app wsgi:app production-check
docker run --rm "${docker_args[@]}" "${IMAGE}" \
    python -m flask --app admin_wsgi:app production-check
docker run --rm "${migration_docker_args[@]}" "${IMAGE}" \
    python -m flask --app wsgi:app verify-runtime-db-privileges

docker run --detach --name "${app_container}" \
    "${docker_args[@]}" "${IMAGE}" "${app_command[@]}" >/dev/null
docker run --detach --name "${admin_container}" \
    "${docker_args[@]}" "${IMAGE}" "${admin_command[@]}" >/dev/null
ready=0
for _ in $(seq 1 20); do
    if docker exec "${app_container}" python -c \
        "import urllib.request; request=urllib.request.Request('http://127.0.0.1:5000/health/ready', headers={'X-Forwarded-Proto':'https'}); urllib.request.urlopen(request, timeout=4).read()" \
        >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done
if [[ "${ready}" -ne 1 ]]; then
    echo "SITBank application did not become ready within 20 seconds" >&2
    false
fi
admin_ready=0
for _ in $(seq 1 20); do
    if docker exec "${admin_container}" python -c \
        "import urllib.request; request=urllib.request.Request('http://127.0.0.1:5002/health/ready', headers={'X-Forwarded-Proto':'https','Host':'admin-sitbank.duckdns.org'}); urllib.request.urlopen(request, timeout=4).read()" \
        >/dev/null 2>&1; then
        admin_ready=1
        break
    fi
    sleep 1
done
if [[ "${admin_ready}" -ne 1 ]]; then
    echo "SITBank admin application did not become ready within 20 seconds" >&2
    false
fi

if [[ "${RUN_ZAP_DAST:-false}" == "true" ]]; then
    dast_base_url="http://${app_container}:5000"
    if ! wait_for_app_from_smoke_network "${dast_base_url}"; then
        echo "SITBank application was not reachable from the DAST smoke network" >&2
        false
    fi
    install -d -m 0777 "${work_dir}/dast"
    dast_mount_source="$(docker_bind_source "${work_dir}/dast")"
    docker run --rm "${docker_args[@]}" \
        --volume "${create_dast_session_source}:/app/create_dast_session.py:ro" \
        --volume "${dast_mount_source}:/run/dast:rw" \
        "${IMAGE}" \
        python /app/create_dast_session.py \
            --base-url "${dast_base_url}" \
            --allow-host "${app_container}" \
            --output /run/dast/auth-cookie
    dast_cookie="$(
        docker run --rm --interactive "${docker_args[@]}" \
            --volume "${dast_mount_source}:/run/dast:ro" \
            "${IMAGE}" \
            python - <<'PY'
from pathlib import Path

print(Path("/run/dast/auth-cookie").read_text(encoding="utf-8"), end="")
PY
    )"
    if [[ ! "${dast_cookie}" =~ ^__Host-sitbank_session=[A-Za-z0-9._~-]+$ ]]; then
        echo "Authenticated DAST session cookie is malformed" >&2
        exit 1
    fi
    install -d -m 0777 "${work_dir}/zap"
    zap_mount_source="$(docker_bind_source "${work_dir}/zap")"
    docker run --rm --network "${network_name}" \
        --volume "${zap_mount_source}:/zap/wrk:rw" \
        "${ZAP_IMAGE}" \
        zap-full-scan.py \
            -t "http://${app_container}:5000/dashboard" \
            -I \
            -m 2 \
            -r zap-report.html \
            -J zap-report.json \
            -z "-config replacer.full_list(0).description=authenticated-session \
-config replacer.full_list(0).enabled=true \
-config replacer.full_list(0).matchtype=REQ_HEADER \
-config replacer.full_list(0).matchstr=Cookie \
-config replacer.full_list(0).replacement=${dast_cookie} \
-config replacer.full_list(1).description=trusted-https-proxy \
-config replacer.full_list(1).enabled=true \
-config replacer.full_list(1).matchtype=REQ_HEADER \
-config replacer.full_list(1).matchstr=X-Forwarded-Proto \
-config replacer.full_list(1).replacement=https"
    unset dast_cookie
fi
