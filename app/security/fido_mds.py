from __future__ import annotations

import base64
import binascii
import json
from datetime import date
from pathlib import Path
from typing import Any
from uuid import UUID


DANGEROUS_STATUSES = {
    "ATTESTATION_KEY_COMPROMISE",
    "REVOKED",
    "USER_KEY_PHYSICAL_COMPROMISE",
    "USER_KEY_REMOTE_COMPROMISE",
    "USER_VERIFICATION_BYPASS",
}

TRUSTED_CERTIFICATION_STATUSES = {
    "FIDO_CERTIFIED_L2",
    "FIDO_CERTIFIED_L2plus",
    "FIDO_CERTIFIED_L3",
    "FIDO_CERTIFIED_L3plus",
}

ATTESTATION_FORMAT_PACKED = "packed"
ATTESTATION_FORMAT_FIDO_U2F = "fido-u2f"
ATTESTATION_FORMAT_TPM = "tpm"
ATTESTATION_FORMAT_ANDROID_KEY = "android-key"
ATTESTATION_FORMAT_ANDROID_SAFETYNET = "android-safetynet"
ATTESTATION_FORMAT_APPLE = "apple"

ATTESTATION_FORMATS_REQUIRING_ROOTS = {
    ATTESTATION_FORMAT_PACKED,
    ATTESTATION_FORMAT_FIDO_U2F,
    ATTESTATION_FORMAT_TPM,
    ATTESTATION_FORMAT_ANDROID_KEY,
    ATTESTATION_FORMAT_ANDROID_SAFETYNET,
    ATTESTATION_FORMAT_APPLE,
}


class FidoMetadataError(ValueError):
    pass


def normalize_aaguid(value: str) -> str:
    try:
        return str(UUID(str(value)))
    except ValueError as exc:
        raise FidoMetadataError("Invalid authenticator AAGUID") from exc


def pem_root_certs_by_fmt() -> dict[str, list[bytes]]:
    cache = _mds_cache()
    approved = _approved_aaguids()
    roots: list[bytes] = []

    for entry in cache.get("entries", []):
        aaguid = _entry_aaguid(entry)
        if not aaguid or aaguid not in approved:
            continue
        roots.extend(_entry_root_certificates(entry))

    return {
        ATTESTATION_FORMAT_PACKED: roots,
        ATTESTATION_FORMAT_FIDO_U2F: roots,
        ATTESTATION_FORMAT_TPM: roots,
        ATTESTATION_FORMAT_ANDROID_KEY: roots,
        ATTESTATION_FORMAT_ANDROID_SAFETYNET: roots,
        ATTESTATION_FORMAT_APPLE: roots,
    }


def validate_aaguid_policy(aaguid: str, attestation_format: str) -> None:
    normalized = normalize_aaguid(aaguid)
    approved, legacy_level1 = _approved_aaguid_policy()
    is_legacy_level1 = normalized in legacy_level1
    if normalized not in approved and not is_legacy_level1:
        raise FidoMetadataError("Authenticator AAGUID is not approved")

    cache = _mds_cache()
    if _cache_is_stale(cache):
        raise FidoMetadataError("FIDO metadata cache is stale")

    entry = _entry_for_aaguid(cache, normalized)
    if entry is None:
        if is_legacy_level1:
            return
        raise FidoMetadataError("Authenticator AAGUID is not present in FIDO metadata cache")

    statuses = _entry_statuses(entry)
    if statuses & DANGEROUS_STATUSES:
        raise FidoMetadataError("Authenticator metadata reports a compromised or revoked status")
    if not statuses & TRUSTED_CERTIFICATION_STATUSES and not (
        is_legacy_level1 and "FIDO_CERTIFIED" in statuses
    ):
        raise FidoMetadataError("Authenticator does not meet the required FIDO certification level")

    fmt = str(attestation_format or "").strip().casefold()
    if fmt in ATTESTATION_FORMATS_REQUIRING_ROOTS and not _entry_root_certificates(entry):
        raise FidoMetadataError("Authenticator metadata lacks attestation trust roots")


def validate_fido_metadata_config() -> int:
    return 0


def _approved_aaguids() -> set[str]:
    approved, legacy_level1 = _approved_aaguid_policy()
    return approved | legacy_level1


def _approved_aaguid_policy() -> tuple[set[str], set[str]]:
    return set(), set()


def _mds_cache() -> dict[str, Any]:
    return {"entries": [], "nextUpdate": str(date.max)}


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FidoMetadataError(f"FIDO metadata file not found: {path}") from exc
    except PermissionError as exc:
        raise FidoMetadataError(f"FIDO metadata file is not readable: {path}") from exc
    except OSError as exc:
        raise FidoMetadataError(f"FIDO metadata file could not be read: {path}") from exc
    except json.JSONDecodeError as exc:
        raise FidoMetadataError(f"FIDO metadata file is invalid JSON: {path}") from exc


def _cache_is_stale(cache: dict[str, Any]) -> bool:
    next_update = cache.get("nextUpdate") or cache.get("next_update")
    if not next_update:
        return True
    try:
        return date.fromisoformat(str(next_update)) < date.today()
    except ValueError:
        return True


def _entry_for_aaguid(cache: dict[str, Any], aaguid: str) -> dict[str, Any] | None:
    for entry in cache.get("entries", []):
        if _entry_aaguid(entry) == aaguid:
            return entry
    return None


def _entry_aaguid(entry: dict[str, Any]) -> str | None:
    value = entry.get("aaguid") or entry.get("metadataStatement", {}).get("aaguid")
    if not value:
        return None
    try:
        return normalize_aaguid(str(value))
    except FidoMetadataError:
        return None


def _entry_statuses(entry: dict[str, Any]) -> set[str]:
    reports = entry.get("statusReports") or entry.get("status_reports") or []
    return {str(report.get("status", "")).strip() for report in reports if report.get("status")}


def _entry_root_certificates(entry: dict[str, Any]) -> list[bytes]:
    statement = entry.get("metadataStatement") or entry.get("metadata_statement") or {}
    values = statement.get("attestationRootCertificates") or statement.get(
        "attestation_root_certificates",
        [],
    )
    roots: list[bytes] = []
    for value in values:
        roots.append(_base64_der_to_pem(str(value)))
    return roots


def _base64_der_to_pem(value: str) -> bytes:
    try:
        der = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise FidoMetadataError("Authenticator metadata contains an invalid attestation root certificate") from exc
    encoded = base64.b64encode(der).decode("ascii")
    lines = [encoded[index : index + 64] for index in range(0, len(encoded), 64)]
    return ("-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n").encode(
        "ascii"
    )
