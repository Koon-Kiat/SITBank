#!/usr/bin/env bash
set -Eeuo pipefail

readonly IMAGE="${1:?Usage: validate-compose.sh IMAGE [production|staging|all]}"
readonly TARGET="${2:-all}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly VALIDATION_OVERRIDE="${repo_root}/ops/container/compose-validation.override.yml"

case "${TARGET}" in
    production|staging|all)
        ;;
    *)
        echo "Compose validation target must be production, staging, or all" >&2
        exit 2
        ;;
esac

validate_model() {
    local project_name="$1"
    local compose_file="$2"
    SITBANK_IMAGE="${IMAGE}" docker compose \
        --project-name "${project_name}" \
        --file "${compose_file}" \
        --file "${VALIDATION_OVERRIDE}" \
        config --quiet --no-env-resolution --no-path-resolution
}

if [[ "${TARGET}" == "production" || "${TARGET}" == "all" ]]; then
    validate_model sitbank "${repo_root}/compose.prod.yml"
fi
if [[ "${TARGET}" == "staging" || "${TARGET}" == "all" ]]; then
    validate_model sitbank-staging "${repo_root}/compose.staging.yml"
fi
