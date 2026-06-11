#!/usr/bin/env bash
set -Eeuo pipefail

readonly IMAGE="${1:?Usage: validate-compose.sh IMAGE}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

sudo install -d -m 0755 /etc/sitbank
sudo install -d -m 0700 /etc/sitbank/secrets
sudo tee /etc/sitbank/container.env > /dev/null <<'EOF'
APP_ENV=production
COMMON_PASSWORDS_MIN_ENTRIES=100000
COMMON_PASSWORDS_PATH=/run/config/common-passwords.txt
HIBP_CIRCUIT_FAILURE_THRESHOLD=3
HIBP_CIRCUIT_OPEN_SECONDS=300
HIBP_PASSWORD_CHECK_TIMEOUT_SECONDS=2.0
MFA_ISSUER_NAME=SITBank
PASSWORD_PBKDF2_ITERATIONS=600000
SESSION_HMAC_ACTIVE_KEY_ID=smoke
TRUSTED_PROXY_COUNT=1
WEBAUTHN_APPROVED_AAGUIDS_PATH=/run/config/fido-approved-aaguids.json
WEBAUTHN_MDS_CACHE_PATH=/run/config/fido-mds-cache.json
WEBAUTHN_RP_ID=sitbank.duckdns.org
WEBAUTHN_RP_ORIGIN=https://sitbank.duckdns.org
EOF
for name in \
    secret_key \
    wtf_csrf_secret_key \
    session_hmac_keys_json \
    database_url \
    redis_url \
    mfa_aes256_gcm_key_b64 \
    password_pepper_b64; do
    printf '%s' 'compose-validation-placeholder' \
        | sudo tee "/etc/sitbank/secrets/${name}" > /dev/null
    sudo chmod 0400 "/etc/sitbank/secrets/${name}"
done
sudo chmod 0600 /etc/sitbank/container.env

sudo env SITBANK_IMAGE="${IMAGE}" \
    docker compose --file "${repo_root}/compose.prod.yml" config --quiet
