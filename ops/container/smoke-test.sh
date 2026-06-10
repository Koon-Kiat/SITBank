#!/usr/bin/env bash
set -Eeuo pipefail

readonly IMAGE="${1:-sitbank:smoke}"
readonly POSTGRES_IMAGE="postgres:16.9-alpine@sha256:7c688148e5e156d0e86df7ba8ae5a05a2386aaec1e2ad8e6d11bdf10504b1fb7"
readonly REDIS_IMAGE="redis:7.4.5-alpine@sha256:bb186d083732f669da90be8b0f975a37812b15e913465bb14d845db72a4e3e08"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work_dir="$(mktemp -d)"
# shellcheck disable=SC2317
cleanup() {
    docker rm -f sitbank-smoke smoke-postgres smoke-redis >/dev/null 2>&1 || true
    rm -rf -- "${work_dir}"
}
trap cleanup EXIT

docker run --detach --name smoke-postgres \
    --publish 127.0.0.1:55432:5432 \
    --env POSTGRES_USER=ci \
    --env POSTGRES_PASSWORD=ci-password \
    --env POSTGRES_DB=ci \
    "${POSTGRES_IMAGE}" >/dev/null
docker run --detach --name smoke-redis \
    --publish 127.0.0.1:56379:6379 \
    "${REDIS_IMAGE}" \
    redis-server --requirepass ci-password >/dev/null

for _ in $(seq 1 30); do
    if docker exec smoke-postgres pg_isready --username ci --dbname ci >/dev/null 2>&1 \
        && docker exec smoke-redis redis-cli -a ci-password ping 2>/dev/null \
            | grep -q PONG; then
        break
    fi
    sleep 1
done
docker exec smoke-postgres pg_isready --username ci --dbname ci >/dev/null
docker exec smoke-redis redis-cli -a ci-password ping 2>/dev/null | grep -q PONG

install -d -m 0755 "${work_dir}/secrets" "${work_dir}/config"
printf '%s' 'ci-secret-key-that-is-long-enough-for-container-tests' \
    > "${work_dir}/secrets/secret_key"
printf '%s' 'ci-csrf-key-that-is-long-enough-for-container-tests' \
    > "${work_dir}/secrets/wtf_csrf_secret_key"
printf '%s' '{"ci":"MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjI="}' \
    > "${work_dir}/secrets/session_hmac_keys_json"
printf '%s' 'postgresql+psycopg2://ci:ci-password@127.0.0.1:55432/ci' \
    > "${work_dir}/secrets/database_url"
printf '%s' 'redis://:ci-password@127.0.0.1:56379/15' \
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

docker logs sitbank-smoke
exit 1
