#!/usr/bin/env bash
set -Eeuo pipefail

readonly IMAGE="${1:-sitbank:smoke}"
readonly POSTGRES_IMAGE="postgres:16.9-alpine@sha256:7c688148e5e156d0e86df7ba8ae5a05a2386aaec1e2ad8e6d11bdf10504b1fb7"
readonly REDIS_IMAGE="redis:7.4.5-alpine@sha256:bb186d083732f669da90be8b0f975a37812b15e913465bb14d845db72a4e3e08"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work_dir="$(mktemp -d)"

dump_container_diagnostics() {
    local container
    for container in smoke-postgres smoke-redis sitbank-smoke; do
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
    docker rm -f sitbank-smoke smoke-postgres smoke-redis >/dev/null 2>&1 || true
    rm -rf -- "${work_dir}"
}
trap cleanup EXIT
trap on_error ERR

docker run --detach --name smoke-postgres \
    --publish 127.0.0.1::5432 \
    --env POSTGRES_USER=ci \
    --env POSTGRES_PASSWORD=ci-password \
    --env POSTGRES_DB=ci \
    --health-cmd "pg_isready --username ci --dbname ci" \
    --health-interval 1s \
    --health-timeout 3s \
    --health-start-period 2s \
    --health-retries 30 \
    "${POSTGRES_IMAGE}" >/dev/null
docker run --detach --name smoke-redis \
    --publish 127.0.0.1::6379 \
    --health-cmd "REDISCLI_AUTH=ci-password redis-cli ping | grep -q PONG" \
    --health-interval 1s \
    --health-timeout 3s \
    --health-start-period 2s \
    --health-retries 30 \
    "${REDIS_IMAGE}" \
    redis-server --requirepass ci-password >/dev/null

wait_for_healthy smoke-postgres
wait_for_healthy smoke-redis
postgres_port="$(published_port smoke-postgres 5432)"
redis_port="$(published_port smoke-redis 6379)"

install -d -m 0755 "${work_dir}/secrets" "${work_dir}/config"
printf '%s' 'ci-secret-key-that-is-long-enough-for-container-tests' \
    > "${work_dir}/secrets/secret_key"
printf '%s' 'ci-csrf-key-that-is-long-enough-for-container-tests' \
    > "${work_dir}/secrets/wtf_csrf_secret_key"
printf '%s' '{"ci":"MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjI="}' \
    > "${work_dir}/secrets/session_hmac_keys_json"
printf 'postgresql+psycopg2://ci:ci-password@127.0.0.1:%s/ci' "${postgres_port}" \
    > "${work_dir}/secrets/database_url"
printf 'redis://:ci-password@127.0.0.1:%s/15' "${redis_port}" \
    > "${work_dir}/secrets/redis_url"
printf '%s' 'MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=' \
    > "${work_dir}/secrets/mfa_aes256_gcm_key_b64"
printf '%s' 'MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=' \
    > "${work_dir}/secrets/password_pepper_b64"
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
    --read-only
    --tmpfs "/tmp:rw,noexec,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=1770"
    --cap-drop ALL
    --security-opt no-new-privileges:true
    --env APP_ENV=production
    --env SECRET_KEY_FILE=/run/secrets/secret_key
    --env WTF_CSRF_SECRET_KEY_FILE=/run/secrets/wtf_csrf_secret_key
    --env SESSION_HMAC_ACTIVE_KEY_ID=ci
    --env SESSION_HMAC_KEYS_JSON_FILE=/run/secrets/session_hmac_keys_json
    --env DATABASE_URL_FILE=/run/secrets/database_url
    --env REDIS_URL_FILE=/run/secrets/redis_url
    --env MFA_AES256_GCM_KEY_B64_FILE=/run/secrets/mfa_aes256_gcm_key_b64
    --env PASSWORD_PEPPER_B64_FILE=/run/secrets/password_pepper_b64
    --env PASSWORD_PBKDF2_ITERATIONS=600000
    --env COMMON_PASSWORDS_PATH=/run/config/common-passwords.txt
    --env COMMON_PASSWORDS_MIN_ENTRIES=100000
    --env WEBAUTHN_RP_ID=sitbank.duckdns.org
    --env WEBAUTHN_RP_ORIGIN=https://sitbank.duckdns.org
    --env WEBAUTHN_APPROVED_AAGUIDS_PATH=/run/config/fido-approved-aaguids.json
    --env WEBAUTHN_MDS_CACHE_PATH=/run/config/fido-mds-cache.json
    --env TRUSTED_PROXY_COUNT=1
    --volume "${work_dir}/secrets:/run/secrets:ro"
    --volume "${work_dir}/config:/run/config:ro"
)

docker run --rm "${docker_args[@]}" "${IMAGE}" \
    python -m flask --app wsgi:app db upgrade
docker run --rm "${docker_args[@]}" "${IMAGE}" \
    python -m flask --app wsgi:app production-check
docker run --rm "${docker_args[@]}" \
    --volume "${repo_root}/ops/container/redis_compatibility_check.py:/app/redis_compatibility_check.py:ro" \
    "${IMAGE}" python /app/redis_compatibility_check.py

docker run --detach --name sitbank-smoke \
    "${docker_args[@]}" "${IMAGE}" >/dev/null
for _ in $(seq 1 20); do
    if curl --fail --silent \
        --header "X-Forwarded-Proto: https" \
        http://127.0.0.1:5000/health/ready >/dev/null; then
        exit 0
    fi
    sleep 1
done

echo "SITBank application did not become ready within 20 seconds" >&2
false
