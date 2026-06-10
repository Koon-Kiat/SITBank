from __future__ import annotations

import json
import re
import hashlib
import secrets
from datetime import datetime, timezone
from typing import Any

from flask import current_app, request, session
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, options_to_json_dict
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    CredentialDeviceType,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialHint,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.extensions import db
from app.models import User, WebAuthnCredential
from app.security.audit import audit_webauthn_event
from app.security.fido_mds import FidoMetadataError, pem_root_certs_by_fmt, validate_aaguid_policy
from app.security.sessions import (
    current_session_id,
    establish_authenticated_session,
    has_recent_fresh_mfa,
    public_session_reference,
    refresh_session_risk_fingerprint,
    revoke_all_sessions,
    revoke_current_session,
)

from .services import AuthError, ensure_account_can_authenticate, ensure_account_not_frozen


LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()#:/+\-]{0,79}$")
GENERIC_WEBAUTHN_ERROR = "Security key verification failed"
REGISTRATION_CHALLENGE_KEY = "webauthn_registration_challenge"
REGISTRATION_LABEL_KEY = "webauthn_registration_label"
REGISTRATION_USER_KEY = "webauthn_registration_user_id"
AUTH_CHALLENGE_KEY = "webauthn_authentication_challenge"
AUTH_USER_KEY = "webauthn_authentication_user_id"
SESSION_CREDENTIAL_KEY = "webauthn_credential_id"
SECURITY_KEY_VERIFIED_AT_KEY = "security_key_verified_at"
TRANSACTION_CHALLENGE_KEY = "webauthn_transaction_challenge"
TRANSACTION_CONTEXT_KEY = "webauthn_transaction_context"
TRANSACTION_USER_KEY = "webauthn_transaction_user_id"
TRANSACTION_CONTEXT_PREFIX = "ospbank:transaction_context:"
STEP_UP_CHALLENGE_KEY = "webauthn_step_up_challenge"
STEP_UP_ACTION_KEY = "webauthn_step_up_action"
STEP_UP_USER_KEY = "webauthn_step_up_user_id"
STEP_UP_TOKEN_PREFIX = "ospbank:webauthn_stepup:"
STEP_UP_ACTIONS = frozenset(
    {
        "password_change",
        "profile_update",
        "mfa_replace_start",
        "session_revoke_others",
        "account_freeze",
        "webauthn_revoke",
    }
)


def enforce_request_origin() -> None:
    origin = request.headers.get("Origin")
    if origin != current_app.config["WEBAUTHN_RP_ORIGIN"]:
        audit_webauthn_event("origin_check", "failure", metadata={"origin": origin})
        raise AuthError("Invalid request origin", 403)


def _redis():
    return current_app.extensions["redis"]


def webauthn_credential_count(user: User) -> int:
    return int(
        db.session.execute(
            db.select(func.count(WebAuthnCredential.id)).where(WebAuthnCredential.user_id == user.id)
        ).scalar_one()
    )


def has_webauthn_credentials(user: User) -> bool:
    return webauthn_credential_count(user) > 0


def has_full_webauthn_access(user: User) -> bool:
    return webauthn_credential_count(user) >= current_app.config.get("WEBAUTHN_REQUIRED_CREDENTIALS", 2)


def needs_security_key_setup(user: User) -> bool:
    if not current_app.config.get("WEBAUTHN_ENFORCE_KEY_SETUP", False):
        return False
    return not has_full_webauthn_access(user)


def current_webauthn_credential_reference() -> str | None:
    value = session.get(SESSION_CREDENTIAL_KEY)
    return str(value) if value else None


def begin_registration_options(user: User, label: str) -> dict[str, Any]:
    enforce_request_origin()
    ensure_account_not_frozen(user, "security key registration")
    label = _validate_label(label)
    _ensure_registration_session_allowed(user)
    _ensure_label_available(user, label)

    credentials = _credentials_for_user(user)
    options = generate_registration_options(
        rp_id=current_app.config["WEBAUTHN_RP_ID"],
        rp_name=current_app.config["WEBAUTHN_RP_NAME"],
        user_id=user.id.to_bytes(8, "big", signed=False),
        user_name=user.username,
        user_display_name=user.username,
        timeout=current_app.config["WEBAUTHN_TIMEOUT_MS"],
        attestation=AttestationConveyancePreference.DIRECT,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=item.credential_id) for item in credentials],
        hints=[PublicKeyCredentialHint.SECURITY_KEY],
    )

    session[REGISTRATION_CHALLENGE_KEY] = bytes_to_base64url(options.challenge)
    session[REGISTRATION_LABEL_KEY] = label
    session[REGISTRATION_USER_KEY] = user.id
    session.modified = True
    audit_webauthn_event("register_options", "success", user=user, label=label)
    return options_to_json_dict(options)


def verify_registration(user: User, credential: dict[str, Any]) -> dict[str, Any]:
    enforce_request_origin()
    ensure_account_not_frozen(user, "security key registration")
    if session.get(REGISTRATION_USER_KEY) != user.id or not session.get(REGISTRATION_CHALLENGE_KEY):
        audit_webauthn_event("register", "failure", user=user, metadata={"reason": "missing_challenge"})
        raise AuthError("No active security key registration challenge", 401)

    label = str(session.get(REGISTRATION_LABEL_KEY) or "")
    _ensure_registration_session_allowed(user)
    _ensure_label_available(user, label)
    _enforce_cross_platform_attachment(credential)

    verification = None
    failure_stage = "attestation_verification"
    try:
        # Direct attestation is verified before the AAGUID is accepted against local MDS policy.
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(str(session[REGISTRATION_CHALLENGE_KEY])),
            expected_rp_id=current_app.config["WEBAUTHN_RP_ID"],
            expected_origin=current_app.config["WEBAUTHN_RP_ORIGIN"],
            require_user_verification=True,
            pem_root_certs_bytes_by_fmt=pem_root_certs_by_fmt(),
        )
        failure_stage = "single_device_policy"
        _enforce_single_device_credential(verification.credential_device_type, verification.credential_backed_up)
        failure_stage = "metadata_policy"
        validate_aaguid_policy(verification.aaguid, verification.fmt)
    except AuthError:
        raise
    except (InvalidRegistrationResponse, FidoMetadataError, ValueError) as exc:
        audit_webauthn_event(
            "register",
            "failure",
            user=user,
            label=label,
            metadata=_registration_failure_metadata(exc, verification, failure_stage),
        )
        raise AuthError(GENERIC_WEBAUTHN_ERROR, 401) from exc

    transports = _registration_transports(credential)
    item = WebAuthnCredential(
        user_id=user.id,
        credential_id=verification.credential_id,
        credential_public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        label=label,
        aaguid=verification.aaguid,
        attestation_format=_enum_value(verification.fmt),
        transports=transports,
        credential_device_type=_enum_value(verification.credential_device_type),
        credential_backed_up=verification.credential_backed_up,
    )
    db.session.add(item)
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        audit_webauthn_event(
            "register",
            "failure",
            user=user,
            credential_id=verification.credential_id,
            label=label,
            aaguid=verification.aaguid,
            metadata={"reason": "duplicate_or_integrity_error"},
        )
        raise AuthError("Security key could not be registered with those details", 409) from exc

    session.pop(REGISTRATION_CHALLENGE_KEY, None)
    session.pop(REGISTRATION_LABEL_KEY, None)
    session.pop(REGISTRATION_USER_KEY, None)
    session.modified = True
    audit_webauthn_event(
        "register",
        "success",
        user=user,
        credential_id=item.credential_id,
        label=item.label,
        aaguid=item.aaguid,
    )
    return {
        "message": "Security key registered",
        "credential": _public_credential(item),
        "requires_backup_key": webauthn_credential_count(user) < current_app.config.get("WEBAUTHN_REQUIRED_CREDENTIALS", 2),
    }


def begin_authentication_options(identifier: str) -> dict[str, Any]:
    enforce_request_origin()
    user = _find_user_by_identifier(identifier)
    credentials: list[WebAuthnCredential] = []
    registered_count = 0
    user_id: int | None = None
    if user is not None:
        try:
            ensure_account_can_authenticate(user)
        except AuthError:
            user = None
    if user is not None:
        user_credentials = _credentials_for_user(user)
        registered_count = len(user_credentials)
        if registered_count >= _required_webauthn_login_credential_count():
            credentials = user_credentials
            user_id = user.id

    options = generate_authentication_options(
        rp_id=current_app.config["WEBAUTHN_RP_ID"],
        timeout=current_app.config["WEBAUTHN_TIMEOUT_MS"],
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                id=item.credential_id,
                transports=_transports_for_descriptor(item),
            )
            for item in credentials
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    session[AUTH_CHALLENGE_KEY] = bytes_to_base64url(options.challenge)
    session[AUTH_USER_KEY] = user_id
    session.modified = True
    audit_webauthn_event(
        "authenticate_options",
        "success",
        user=user,
        metadata={
            "credential_count": len(credentials),
            "registered_credential_count": registered_count,
            "required_credential_count": _required_webauthn_login_credential_count(),
        },
    )
    return options_to_json_dict(options)


def verify_authentication(credential: dict[str, Any]) -> dict[str, Any]:
    enforce_request_origin()
    challenge = session.get(AUTH_CHALLENGE_KEY)
    pending_user_id = session.get(AUTH_USER_KEY)
    if not challenge or not pending_user_id:
        audit_webauthn_event("authenticate", "failure", metadata={"reason": "missing_challenge"})
        raise AuthError(GENERIC_WEBAUTHN_ERROR, 401)

    credential_id = _credential_id_from_payload(credential)
    item = db.session.execute(
        db.select(WebAuthnCredential).where(
            WebAuthnCredential.user_id == int(pending_user_id),
            WebAuthnCredential.credential_id == credential_id,
        )
    ).scalar_one_or_none()
    if item is None:
        audit_webauthn_event(
            "authenticate",
            "failure",
            user_id=int(pending_user_id),
            credential_id=credential_id,
            metadata={"reason": "unknown_or_unowned_credential"},
        )
        raise AuthError(GENERIC_WEBAUTHN_ERROR, 401)

    user = db.session.get(User, item.user_id)
    if user is None:
        audit_webauthn_event(
            "authenticate",
            "failure",
            user_id=item.user_id,
            credential_id=item.credential_id,
            metadata={"reason": "missing_user"},
        )
        raise AuthError(GENERIC_WEBAUTHN_ERROR, 401)
    try:
        ensure_account_can_authenticate(user)
    except AuthError as exc:
        audit_webauthn_event(
            "authenticate",
            "failure",
            user=user,
            credential_id=item.credential_id,
            metadata={"reason": "account_locked_or_frozen"},
        )
        raise AuthError(GENERIC_WEBAUTHN_ERROR, 401) from exc

    registered_count = webauthn_credential_count(user)
    required_count = _required_webauthn_login_credential_count()
    if registered_count < required_count:
        audit_webauthn_event(
            "authenticate",
            "failure",
            user=user,
            credential_id=item.credential_id,
            label=item.label,
            aaguid=item.aaguid,
            metadata={
                "reason": "insufficient_security_keys",
                "registered_credential_count": registered_count,
                "required_credential_count": required_count,
            },
        )
        raise AuthError(GENERIC_WEBAUTHN_ERROR, 401)

    try:
        # py_webauthn rejects stale counters; the explicit check keeps monkeypatched tests and
        # future library behavior aligned with the MAS clone-response lockout requirement.
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(str(challenge)),
            expected_rp_id=current_app.config["WEBAUTHN_RP_ID"],
            expected_origin=current_app.config["WEBAUTHN_RP_ORIGIN"],
            credential_public_key=item.credential_public_key,
            credential_current_sign_count=item.sign_count,
            require_user_verification=True,
        )
        _enforce_single_device_credential(
            verification.credential_device_type,
            verification.credential_backed_up,
        )
        if verification.new_sign_count <= item.sign_count:
            _lock_for_counter_anomaly(user, item, verification.new_sign_count)
    except AuthError:
        raise
    except InvalidAuthenticationResponse as exc:
        if "sign count" in str(exc).casefold():
            _lock_for_counter_anomaly(user, item, item.sign_count)
        audit_webauthn_event(
            "authenticate",
            "failure",
            user=user,
            credential_id=item.credential_id,
            label=item.label,
            aaguid=item.aaguid,
            metadata={"reason": type(exc).__name__},
        )
        raise AuthError(GENERIC_WEBAUTHN_ERROR, 401) from exc
    except (ValueError, FidoMetadataError) as exc:
        audit_webauthn_event(
            "authenticate",
            "failure",
            user=user,
            credential_id=item.credential_id,
            label=item.label,
            aaguid=item.aaguid,
            metadata={"reason": type(exc).__name__},
        )
        raise AuthError(GENERIC_WEBAUTHN_ERROR, 401) from exc

    item.sign_count = verification.new_sign_count
    item.last_used_at = datetime.now(timezone.utc)
    item.credential_device_type = _enum_value(verification.credential_device_type)
    item.credential_backed_up = verification.credential_backed_up
    user.failed_login_count = 0
    user.last_login_at = datetime.now(timezone.utc)
    db.session.commit()

    session.pop(AUTH_CHALLENGE_KEY, None)
    session.pop(AUTH_USER_KEY, None)
    session_id = establish_authenticated_session(
        user_id=user.id,
        mfa_verified=True,
        auth_context="webauthn",
    )
    session[SESSION_CREDENTIAL_KEY] = bytes_to_base64url(item.credential_id)
    session[SECURITY_KEY_VERIFIED_AT_KEY] = _now_timestamp()
    session.modified = True
    refresh_session_risk_fingerprint()
    audit_webauthn_event(
        "authenticate",
        "success",
        user=user,
        credential_id=item.credential_id,
        label=item.label,
        aaguid=item.aaguid,
        session_id=session_id,
    )
    return {
        "message": "Login successful",
        "session_ref": public_session_reference(session_id),
        "requires_backup_key": webauthn_credential_count(user) < current_app.config.get("WEBAUTHN_REQUIRED_CREDENTIALS", 2),
        "user": _public_user(user),
    }


def begin_step_up_options(user: User, action: str) -> dict[str, Any]:
    enforce_request_origin()
    ensure_account_not_frozen(user, "security key step-up")
    normalized_action = _validate_step_up_action(action)
    _ensure_authenticated_user_session(user, "step_up_options")
    _ensure_step_up_key_access(user, normalized_action)

    credentials = _credentials_for_user(user)
    options = generate_authentication_options(
        rp_id=current_app.config["WEBAUTHN_RP_ID"],
        timeout=current_app.config["WEBAUTHN_TIMEOUT_MS"],
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                id=item.credential_id,
                transports=_transports_for_descriptor(item),
            )
            for item in credentials
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    session[STEP_UP_CHALLENGE_KEY] = bytes_to_base64url(options.challenge)
    session[STEP_UP_ACTION_KEY] = normalized_action
    session[STEP_UP_USER_KEY] = user.id
    session.modified = True
    audit_webauthn_event(
        "step_up_options",
        "success",
        user=user,
        metadata={
            "step_up_action": normalized_action,
            "credential_count": len(credentials),
        },
    )
    payload = options_to_json_dict(options)
    payload["action"] = normalized_action
    return payload


def verify_step_up(user: User, action: str, credential: dict[str, Any]) -> dict[str, Any]:
    enforce_request_origin()
    ensure_account_not_frozen(user, "security key step-up")
    normalized_action = _validate_step_up_action(action)
    _ensure_authenticated_user_session(user, "step_up_verify")
    _ensure_step_up_key_access(user, normalized_action)

    challenge = session.get(STEP_UP_CHALLENGE_KEY)
    pending_user_id = session.get(STEP_UP_USER_KEY)
    pending_action = session.get(STEP_UP_ACTION_KEY)
    if not challenge or pending_user_id != user.id or pending_action != normalized_action:
        audit_webauthn_event(
            "step_up_verify",
            "failure",
            user=user,
            metadata={"reason": "missing_or_mismatched_challenge", "step_up_action": normalized_action},
        )
        raise AuthError(GENERIC_WEBAUTHN_ERROR, 401)

    item = _credential_for_user_payload(user.id, credential, "step_up_verify")
    verification = _verify_assertion_response(user, item, credential, str(challenge), "step_up_verify")
    item.sign_count = verification.new_sign_count
    item.last_used_at = datetime.now(timezone.utc)
    item.credential_device_type = _enum_value(verification.credential_device_type)
    item.credential_backed_up = verification.credential_backed_up
    db.session.commit()

    token = secrets.token_urlsafe(32)
    ttl = int(current_app.config["WEBAUTHN_STEP_UP_TTL_SECONDS"])
    _redis().set(
        _step_up_token_cache_key(token),
        json.dumps(
            {
                "user_id": user.id,
                "session_id": current_session_id(),
                "action": normalized_action,
                "credential_id": bytes_to_base64url(item.credential_id),
                "issued_at": _now_timestamp(),
            }
        ),
        ex=ttl,
    )
    session.pop(STEP_UP_CHALLENGE_KEY, None)
    session.pop(STEP_UP_ACTION_KEY, None)
    session.pop(STEP_UP_USER_KEY, None)
    session[SECURITY_KEY_VERIFIED_AT_KEY] = _now_timestamp()
    session[SESSION_CREDENTIAL_KEY] = bytes_to_base64url(item.credential_id)
    session.modified = True
    refresh_session_risk_fingerprint()
    audit_webauthn_event(
        "step_up_verify",
        "success",
        user=user,
        credential_id=item.credential_id,
        label=item.label,
        aaguid=item.aaguid,
        metadata={"step_up_action": normalized_action},
    )
    return {
        "message": "Security key step-up verified",
        "action": normalized_action,
        "stepup_token": token,
        "expires_in": ttl,
    }


def consume_step_up_token(user: User, action: str, token: str | None) -> None:
    normalized_action = _validate_step_up_action(action)
    _ensure_authenticated_user_session(user, "step_up_consume")
    _ensure_step_up_key_access(user, normalized_action)
    if not token:
        audit_webauthn_event(
            "step_up_consume",
            "failure",
            user=user,
            metadata={"reason": "missing_token", "step_up_action": normalized_action},
        )
        raise AuthError("Security key step-up is required for this action", 403)

    redis_client = _redis()
    key = _step_up_token_cache_key(token)
    raw = redis_client.get(key)
    if not raw:
        audit_webauthn_event(
            "step_up_consume",
            "expired",
            user=user,
            metadata={"step_up_action": normalized_action},
        )
        raise AuthError("Security key step-up is required for this action", 403)
    redis_client.delete(key)

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        audit_webauthn_event(
            "step_up_consume",
            "failure",
            user=user,
            metadata={"reason": "invalid_token_payload", "step_up_action": normalized_action},
        )
        raise AuthError("Security key step-up is required for this action", 403) from exc

    if (
        payload.get("user_id") != user.id
        or payload.get("session_id") != current_session_id()
        or payload.get("action") != normalized_action
    ):
        audit_webauthn_event(
            "step_up_consume",
            "failure",
            user=user,
            metadata={"reason": "token_scope_mismatch", "step_up_action": normalized_action},
        )
        raise AuthError("Security key step-up is required for this action", 403)

    audit_webauthn_event(
        "step_up_consume",
        "success",
        user=user,
        metadata={"step_up_action": normalized_action},
    )


def list_credentials_for_user(user: User) -> list[dict[str, Any]]:
    return [_public_credential(item) for item in _credentials_for_user(user)]


def revoke_credential(
    user: User,
    credential_reference: str,
    stepup_token: str | None = None,
    *,
    stepup_already_consumed: bool = False,
) -> dict[str, Any]:
    ensure_account_not_frozen(user, "security key revocation")
    _ensure_lifecycle_session_allowed(user, "revoke")
    if not stepup_already_consumed:
        consume_step_up_token(user, "webauthn_revoke", stepup_token)
    credential_id = base64url_to_bytes(credential_reference)
    item = db.session.execute(
        db.select(WebAuthnCredential).where(
            WebAuthnCredential.user_id == user.id,
            WebAuthnCredential.credential_id == credential_id,
        )
    ).scalar_one_or_none()
    if item is None:
        audit_webauthn_event(
            "revoke",
            "failure",
            user=user,
            credential_id=credential_reference,
            metadata={"reason": "not_owned_or_not_found"},
        )
        raise AuthError("Security key not found", 404)

    active_count = webauthn_credential_count(user)
    required_count = current_app.config.get("WEBAUTHN_REQUIRED_CREDENTIALS", 2)
    if active_count <= required_count:
        audit_webauthn_event(
            "revoke",
            "failure",
            user=user,
            credential_id=item.credential_id,
            label=item.label,
            aaguid=item.aaguid,
            metadata={
                "reason": "required_key_count_revocation_blocked",
                "registered_credential_count": active_count,
                "required_credential_count": required_count,
            },
        )
        raise AuthError("At least two security keys must remain registered", 409)

    current_ref = current_webauthn_credential_reference()
    is_current_credential = current_ref == credential_reference
    label = item.label
    aaguid = item.aaguid
    db.session.delete(item)
    db.session.commit()
    audit_webauthn_event(
        "revoke",
        "success",
        user=user,
        credential_id=credential_reference,
        label=label,
        aaguid=aaguid,
        metadata={"current_session_credential": is_current_credential},
    )
    if is_current_credential:
        revoke_current_session()
    return {
        "message": "Security key revoked",
        "current_session_revoked": is_current_credential,
        "requires_backup_key": webauthn_credential_count(user) < current_app.config.get("WEBAUTHN_REQUIRED_CREDENTIALS", 2),
    }


def stage_transaction_security_key_context(user: User, transaction_context: dict[str, Any]) -> str:
    ensure_account_not_frozen(user, "transaction staging")
    context = _validate_transaction_context(transaction_context)
    expiry = _parse_transaction_expiry(context["expiry"])
    ttl = max(1, min(int((expiry - datetime.now(timezone.utc)).total_seconds()), current_app.config["WEBAUTHN_TIMEOUT_MS"] // 1000))
    _redis().set(
        _transaction_context_cache_key(user.id, context["transaction_reference"]),
        json.dumps(context),
        ex=ttl,
    )
    audit_webauthn_event(
        "transaction_stage",
        "success",
        user=user,
        metadata=_transaction_audit_metadata(context),
    )
    return context["transaction_reference"]


def begin_transaction_security_key_challenge(user: User, transaction_reference: str) -> dict[str, Any]:
    enforce_request_origin()
    ensure_account_not_frozen(user, "transaction security key challenge")
    _ensure_transaction_session_allowed(user)
    if not isinstance(transaction_reference, str) or not transaction_reference.strip():
        audit_webauthn_event(
            "transaction_options",
            "failure",
            user=user,
            metadata={"reason": "client_supplied_or_missing_reference"},
        )
        raise AuthError("Transaction reference is required", 400)

    context = _load_staged_transaction_context(user.id, transaction_reference)
    credentials = _credentials_for_user(user)
    if not credentials:
        audit_webauthn_event(
            "transaction_options",
            "failure",
            user=user,
            metadata={**_transaction_audit_metadata(context), "reason": "no_registered_security_key"},
        )
        raise AuthError("A registered security key is required to approve this transaction", 403)

    options = generate_authentication_options(
        rp_id=current_app.config["WEBAUTHN_RP_ID"],
        timeout=current_app.config["WEBAUTHN_TIMEOUT_MS"],
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                id=item.credential_id,
                transports=_transports_for_descriptor(item),
            )
            for item in credentials
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    session[TRANSACTION_CHALLENGE_KEY] = bytes_to_base64url(options.challenge)
    session[TRANSACTION_CONTEXT_KEY] = context
    session[TRANSACTION_USER_KEY] = user.id
    session.modified = True
    audit_webauthn_event(
        "transaction_options",
        "success",
        user=user,
        metadata={**_transaction_audit_metadata(context), "credential_count": len(credentials)},
    )
    payload = options_to_json_dict(options)
    payload["transaction_reference"] = context["transaction_reference"]
    return payload


def verify_transaction_security_key_challenge(user: User, credential: dict[str, Any]) -> dict[str, Any]:
    enforce_request_origin()
    ensure_account_not_frozen(user, "transaction security key verification")
    challenge = session.get(TRANSACTION_CHALLENGE_KEY)
    pending_user_id = session.get(TRANSACTION_USER_KEY)
    raw_context = session.get(TRANSACTION_CONTEXT_KEY)
    if not challenge or pending_user_id != user.id or not isinstance(raw_context, dict):
        audit_webauthn_event(
            "transaction_verify",
            "failure",
            user=user,
            metadata={"reason": "missing_challenge"},
        )
        raise AuthError(GENERIC_WEBAUTHN_ERROR, 401)

    context = _validate_transaction_context(raw_context)
    item = _credential_for_user_payload(user.id, credential, "transaction_verify")
    verification = _verify_assertion_response(user, item, credential, str(challenge), "transaction_verify")

    item.sign_count = verification.new_sign_count
    item.last_used_at = datetime.now(timezone.utc)
    item.credential_device_type = _enum_value(verification.credential_device_type)
    item.credential_backed_up = verification.credential_backed_up
    db.session.commit()

    session.pop(TRANSACTION_CHALLENGE_KEY, None)
    session.pop(TRANSACTION_CONTEXT_KEY, None)
    session.pop(TRANSACTION_USER_KEY, None)
    _redis().delete(_transaction_context_cache_key(user.id, context["transaction_reference"]))
    session[SECURITY_KEY_VERIFIED_AT_KEY] = _now_timestamp()
    session[SESSION_CREDENTIAL_KEY] = bytes_to_base64url(item.credential_id)
    session.modified = True
    refresh_session_risk_fingerprint()
    audit_webauthn_event(
        "transaction_verify",
        "success",
        user=user,
        credential_id=item.credential_id,
        label=item.label,
        aaguid=item.aaguid,
        metadata=_transaction_audit_metadata(context),
    )
    return {
        "message": "Transaction security key challenge verified",
        "transaction_reference": context["transaction_reference"],
        "credential_id": bytes_to_base64url(item.credential_id),
    }


def _find_user_by_identifier(identifier: str) -> User | None:
    normalized = identifier.strip().casefold()
    return db.session.execute(
        db.select(User).where(
            or_(
                func.lower(User.username) == normalized,
                func.lower(User.email) == normalized,
            )
        )
    ).scalar_one_or_none()


def _registration_failure_metadata(exc: Exception, verification, failure_stage: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "reason": type(exc).__name__,
        "failure_stage": failure_stage,
        "failure_detail": str(exc)[:240],
    }
    if verification is not None:
        metadata.update(
            {
                "aaguid": str(getattr(verification, "aaguid", "") or ""),
                "attestation_format": _enum_value(getattr(verification, "fmt", "")),
                "credential_device_type": _enum_value(getattr(verification, "credential_device_type", "")),
                "credential_backed_up": bool(getattr(verification, "credential_backed_up", False)),
            }
        )
    return metadata


def _enum_value(value: Any) -> str:
    enum_value = getattr(value, "value", None)
    return str(enum_value if enum_value is not None else value)


def _validate_step_up_action(action: str) -> str:
    normalized = str(action or "").strip()
    if normalized not in STEP_UP_ACTIONS:
        raise AuthError("Invalid security key step-up action", 400)
    return normalized


def _ensure_authenticated_user_session(user: User, action: str) -> None:
    if session.get("user_id") != user.id:
        audit_webauthn_event(action, "failure", user=user, metadata={"reason": "not_authenticated_session"})
        raise AuthError("Authentication required", 401)


def _ensure_step_up_key_access(user: User, action: str) -> None:
    required_count = current_app.config.get("WEBAUTHN_REQUIRED_CREDENTIALS", 2)
    registered_count = webauthn_credential_count(user)
    if registered_count < required_count:
        audit_webauthn_event(
            "step_up_denied",
            "failure",
            user=user,
            metadata={
                "reason": "insufficient_security_keys",
                "step_up_action": action,
                "registered_credential_count": registered_count,
                "required_credential_count": required_count,
            },
        )
        raise AuthError("Two registered security keys are required for this action", 403)


def _step_up_token_cache_key(token: str) -> str:
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return f"{STEP_UP_TOKEN_PREFIX}{digest}"


def _required_webauthn_login_credential_count() -> int:
    return int(current_app.config.get("WEBAUTHN_REQUIRED_CREDENTIALS", 2))


def _credentials_for_user(user: User) -> list[WebAuthnCredential]:
    return list(
        db.session.execute(
            db.select(WebAuthnCredential)
            .where(WebAuthnCredential.user_id == user.id)
            .order_by(WebAuthnCredential.created_at.asc(), WebAuthnCredential.id.asc())
        ).scalars()
    )


def _validate_label(label: str) -> str:
    normalized = " ".join((label or "").strip().split())
    if not LABEL_RE.fullmatch(normalized):
        raise AuthError("Security key label must be 1 to 80 supported characters", 400)
    return normalized


def _ensure_label_available(user: User, label: str) -> None:
    exists = db.session.execute(
        db.select(WebAuthnCredential.id).where(
            WebAuthnCredential.user_id == user.id,
            func.lower(WebAuthnCredential.label) == label.casefold(),
        )
    ).first()
    if exists:
        raise AuthError("Security key label is already in use", 409)


def _ensure_registration_session_allowed(user: User) -> None:
    if session.get("user_id") != user.id:
        audit_webauthn_event("register", "failure", user=user, metadata={"reason": "not_authenticated_session"})
        raise AuthError("Authentication required", 401)

    existing_count = webauthn_credential_count(user)
    if existing_count == 0 and has_recent_fresh_mfa():
        return
    if existing_count > 0 and _has_recent_lifecycle_authorization():
        return
    audit_webauthn_event("register", "failure", user=user, metadata={"reason": "missing_recent_mfa_or_key"})
    raise AuthError("Recent MFA verification is required before managing security keys", 403)


def _ensure_lifecycle_session_allowed(user: User, action: str) -> None:
    if session.get("user_id") != user.id:
        audit_webauthn_event(action, "failure", user=user, metadata={"reason": "not_authenticated_session"})
        raise AuthError("Authentication required", 401)
    if _has_recent_lifecycle_authorization():
        return
    audit_webauthn_event(action, "failure", user=user, metadata={"reason": "missing_recent_mfa_or_key"})
    raise AuthError("Recent MFA verification is required before managing security keys", 403)


def _ensure_transaction_session_allowed(user: User) -> None:
    if session.get("user_id") != user.id:
        audit_webauthn_event("transaction_options", "failure", user=user, metadata={"reason": "not_authenticated_session"})
        raise AuthError("Authentication required", 401)


def _enforce_cross_platform_attachment(credential: dict[str, Any]) -> None:
    attachment = credential.get("authenticatorAttachment")
    if attachment != AuthenticatorAttachment.CROSS_PLATFORM.value:
        raise AuthError("Only cross-platform hardware security keys are allowed", 400)


def _enforce_single_device_credential(
    credential_device_type: CredentialDeviceType | str,
    credential_backed_up: bool,
) -> None:
    value = credential_device_type.value if isinstance(credential_device_type, CredentialDeviceType) else str(credential_device_type)
    if value != CredentialDeviceType.SINGLE_DEVICE.value or credential_backed_up:
        raise FidoMetadataError("Synced or backed-up passkeys are not allowed")


def _registration_transports(credential: dict[str, Any]) -> list[str]:
    response = credential.get("response") or {}
    transports = response.get("transports") or []
    return [str(value)[:32] for value in transports]


def _transports_for_descriptor(item: WebAuthnCredential):
    from webauthn.helpers.structs import AuthenticatorTransport

    transports = []
    for value in item.transports or []:
        try:
            transports.append(AuthenticatorTransport(value))
        except ValueError:
            continue
    return transports or None


def _credential_id_from_payload(credential: dict[str, Any]) -> bytes:
    value = credential.get("id") or credential.get("rawId")
    if not value:
        raise AuthError(GENERIC_WEBAUTHN_ERROR, 401)
    return base64url_to_bytes(str(value))


def _credential_for_user_payload(user_id: int, credential: dict[str, Any], action: str) -> WebAuthnCredential:
    credential_id = _credential_id_from_payload(credential)
    item = db.session.execute(
        db.select(WebAuthnCredential).where(
            WebAuthnCredential.user_id == user_id,
            WebAuthnCredential.credential_id == credential_id,
        )
    ).scalar_one_or_none()
    if item is None:
        audit_webauthn_event(
            action,
            "failure",
            user_id=user_id,
            credential_id=credential_id,
            metadata={"reason": "unknown_or_unowned_credential"},
        )
        raise AuthError(GENERIC_WEBAUTHN_ERROR, 401)
    return item


def _verify_assertion_response(
    user: User,
    item: WebAuthnCredential,
    credential: dict[str, Any],
    challenge: str,
    action: str,
):
    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge),
            expected_rp_id=current_app.config["WEBAUTHN_RP_ID"],
            expected_origin=current_app.config["WEBAUTHN_RP_ORIGIN"],
            credential_public_key=item.credential_public_key,
            credential_current_sign_count=item.sign_count,
            require_user_verification=True,
        )
        _enforce_single_device_credential(
            verification.credential_device_type,
            verification.credential_backed_up,
        )
        if verification.new_sign_count <= item.sign_count:
            _lock_for_counter_anomaly(user, item, verification.new_sign_count)
        return verification
    except AuthError:
        raise
    except InvalidAuthenticationResponse as exc:
        if "sign count" in str(exc).casefold():
            _lock_for_counter_anomaly(user, item, item.sign_count)
        audit_webauthn_event(
            action,
            "failure",
            user=user,
            credential_id=item.credential_id,
            label=item.label,
            aaguid=item.aaguid,
            metadata={"reason": type(exc).__name__},
        )
        raise AuthError(GENERIC_WEBAUTHN_ERROR, 401) from exc
    except (ValueError, FidoMetadataError) as exc:
        audit_webauthn_event(
            action,
            "failure",
            user=user,
            credential_id=item.credential_id,
            label=item.label,
            aaguid=item.aaguid,
            metadata={"reason": type(exc).__name__},
        )
        raise AuthError(GENERIC_WEBAUTHN_ERROR, 401) from exc


def _lock_for_counter_anomaly(user: User, item: WebAuthnCredential, incoming_counter: int) -> None:
    user.is_frozen = True
    user.security_locked_at = datetime.now(timezone.utc)
    user.security_lock_reason = "webauthn_signature_counter_anomaly"
    db.session.commit()
    revoked = revoke_all_sessions(user.id)
    audit_webauthn_event(
        "clone_detected",
        "locked",
        user=user,
        credential_id=item.credential_id,
        label=item.label,
        aaguid=item.aaguid,
        metadata={
            "stored_sign_count": item.sign_count,
            "incoming_sign_count": incoming_counter,
            "revoked_sessions": revoked,
        },
    )
    raise AuthError("Security key anomaly detected. Account locked pending review.", 403)


def _has_recent_lifecycle_authorization() -> bool:
    return has_recent_fresh_mfa() or _has_recent_security_key_verification()


def _has_recent_security_key_verification() -> bool:
    try:
        verified_at = int(session.get(SECURITY_KEY_VERIFIED_AT_KEY) or 0)
    except (TypeError, ValueError):
        return False
    return bool(verified_at and _now_timestamp() - verified_at <= current_app.config["FRESH_MFA_SECONDS"])


def _now_timestamp() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _transaction_context_cache_key(user_id: int, transaction_reference: str) -> str:
    return f"{TRANSACTION_CONTEXT_PREFIX}{user_id}:{transaction_reference}"


def _load_staged_transaction_context(user_id: int, transaction_reference: str) -> dict[str, str]:
    raw = _redis().get(_transaction_context_cache_key(user_id, transaction_reference.strip()))
    if not raw:
        raise AuthError("Transaction security key challenge has expired", 401)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AuthError("Transaction security key context is invalid", 401) from exc
    return _validate_transaction_context(payload)


def _validate_transaction_context(transaction_context: dict[str, Any]) -> dict[str, str]:
    if not isinstance(transaction_context, dict):
        raise AuthError("Transaction security key context is incomplete", 400)
    amount = str(transaction_context.get("amount") or "").strip()
    currency = str(transaction_context.get("currency") or "").strip().upper()
    transaction_reference = str(transaction_context.get("transaction_reference") or "").strip()
    payee_account = str(
        transaction_context.get("payee_account")
        or transaction_context.get("payee")
        or transaction_context.get("account")
        or ""
    ).strip()
    expiry = _parse_transaction_expiry(transaction_context.get("expiry") or transaction_context.get("expires_at"))

    if not amount or not currency or not transaction_reference or not payee_account:
        raise AuthError("Transaction security key context is incomplete", 400)
    if expiry <= datetime.now(timezone.utc):
        raise AuthError("Transaction security key challenge has expired", 401)
    return {
        "amount": amount[:64],
        "currency": currency[:8],
        "payee_account": payee_account[:160],
        "transaction_reference": transaction_reference[:120],
        "expiry": expiry.isoformat(),
    }


def _parse_transaction_expiry(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, int | float):
        parsed = datetime.fromtimestamp(value, timezone.utc)
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise AuthError("Transaction security key expiry is invalid", 400) from exc
    else:
        raise AuthError("Transaction security key context is incomplete", 400)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _transaction_audit_metadata(context: dict[str, str]) -> dict[str, str]:
    return {
        "transaction_amount": context.get("amount", ""),
        "transaction_currency": context.get("currency", ""),
        "transaction_payee_account": context.get("payee_account", ""),
        "transaction_reference": context.get("transaction_reference", ""),
        "transaction_expiry": context.get("expiry", ""),
    }


def _public_credential(item: WebAuthnCredential) -> dict[str, Any]:
    return {
        "credential_id": bytes_to_base64url(item.credential_id),
        "label": item.label,
        "aaguid": item.aaguid,
        "attestation_format": item.attestation_format,
        "transports": item.transports or [],
        "credential_device_type": item.credential_device_type,
        "credential_backed_up": item.credential_backed_up,
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "last_used_at": item.last_used_at.isoformat() if item.last_used_at else None,
        "last_used_at_display": _format_credential_time(item.last_used_at),
        "current": current_webauthn_credential_reference() == bytes_to_base64url(item.credential_id),
    }


def _format_credential_time(value: datetime | None) -> str:
    if value is None:
        return "Never used"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%d %b %Y %H:%M UTC")


def _public_user(user: User) -> dict[str, Any]:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "mfa_enabled": user.mfa_enabled,
        "is_frozen": user.is_frozen,
    }
