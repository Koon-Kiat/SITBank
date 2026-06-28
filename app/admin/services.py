from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import pyotp
from flask import current_app, request, session, url_for
from sqlalchemy import String, cast, func, or_
from sqlalchemy.exc import IntegrityError

from app.auth.password_reset import (
    MANUAL_RECOVERY_ACTIVE_STATUSES,
    MANUAL_RECOVERY_STATUS_APPROVED,
    MANUAL_RECOVERY_STATUS_DENIED,
    MANUAL_RECOVERY_STATUS_UNDER_REVIEW,
    complete_manual_recovery_request,
    transition_manual_recovery_request,
)
from app.auth.services import (
    AuthError,
    _dummy_password_hash,
    _verify_totp_for_user,
)
from app.extensions import db
from app.models import ManualRecoveryRequest, SecurityAuditEvent, StaffInvite, User
from app.security.audit import audit_event, audit_event_required, audit_reference, principal_reference
from app.security.crypto import encrypt_mfa_secret
from app.security.email import send_security_email
from app.security.passwords import (
    PasswordPolicyError,
    hash_password,
    is_password_raw_length_safe,
    password_hash_needs_rehash,
    validate_password_policy,
    verify_password,
)
from app.security.rate_limits import AuthBackoffRequired, apply_exponential_backoff, clear_failures, record_failure
from app.security.session_hmac import active_hmac_hex
from app.security.sessions import (
    begin_password_authenticated_session,
    establish_authenticated_session,
    public_session_reference,
    revoke_all_sessions,
    revoke_current_session,
)
from app.security.turnstile import TurnstileError, verify_turnstile_token


ACCOUNT_CUSTOMER = "customer"
ACCOUNT_STAFF = "staff"
ACCOUNT_ADMIN = "admin"
ACCOUNT_ROOT_ADMIN = "root_admin"
STAFF_ACCOUNT_TYPES = frozenset({ACCOUNT_STAFF, ACCOUNT_ADMIN, ACCOUNT_ROOT_ADMIN})
INVITABLE_ROLES = frozenset({ACCOUNT_STAFF, ACCOUNT_ADMIN})
ROLE_HIERARCHY = {
    ACCOUNT_CUSTOMER: 0,
    ACCOUNT_STAFF: 10,
    ACCOUNT_ADMIN: 20,
    ACCOUNT_ROOT_ADMIN: 30,
}
ADMIN_ACCOUNT_MANAGED_TYPES = frozenset({ACCOUNT_STAFF, ACCOUNT_ADMIN})
ACTIVE_INVITE_STATUSES = frozenset({"pending", "totp_pending"})
MANUAL_RECOVERY_ADMIN_TRANSITION_STATUSES = frozenset(
    {
        MANUAL_RECOVERY_STATUS_UNDER_REVIEW,
        MANUAL_RECOVERY_STATUS_APPROVED,
        MANUAL_RECOVERY_STATUS_DENIED,
    }
)
GENERIC_ADMIN_LOGIN_ERROR = "Invalid workplace email, password, or authentication code"
GENERIC_INVITE_ERROR = "Invite link is invalid or expired"
GENERIC_WORKPLACE_VERIFICATION_ERROR = "Workplace verification failed"
ADMIN_AUTH_BACKOFF_ERROR = "Too many attempts. Please try again later."
STAFF_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")
FULL_NAME_RE = re.compile(r"^[^\x00-\x1f\x7f<>]{1,120}$")
PHONE_RE = re.compile(r"^[89][0-9]{7}$")
EMAIL_RE = re.compile(
    r"^(?=\S{1,128}@\S{1,253}$)[^@\x00-\x1f\x7f]+@[^@\x00-\x1f\x7f]+$"
)
TOTP_RE = re.compile(r"^\d{6}$")
WORKPLACE_CODE_RE = re.compile(r"^\d{6}$")


def is_customer_user(user: User | None) -> bool:
    return bool(user is not None and (user.account_type or ACCOUNT_CUSTOMER) == ACCOUNT_CUSTOMER)


def is_staff_user(user: User | None) -> bool:
    return bool(user is not None and (user.account_type or ACCOUNT_CUSTOMER) in STAFF_ACCOUNT_TYPES)


def is_active_staff_user(user: User | None) -> bool:
    return bool(is_staff_user(user) and user.account_status == "active" and user.mfa_enabled)


def is_root_admin(user: User | None) -> bool:
    if user is None or user.account_type != ACCOUNT_ROOT_ADMIN:
        return False
    return _normalize_email(user.email).casefold() in _root_admin_emails()


def require_staff_session() -> User:
    user_id = session.get("user_id")
    if not user_id:
        raise AuthError("Authentication required", 401)
    user = db.session.get(User, int(user_id))
    if not is_active_staff_user(user):
        audit_event("admin_access_denied", "blocked", user=user, metadata={"reason": "not_active_staff"})
        raise AuthError("Forbidden", 403)
    return user


def require_root_admin_session() -> User:
    user = require_staff_session()
    if not is_root_admin(user):
        audit_event("staff_invite_authorization", "blocked", user=user, metadata={"reason": "not_root_admin"})
        raise AuthError("Forbidden", 403)
    return user


def require_admin_session() -> User:
    user = require_staff_session()
    if role_rank(user.account_type) < role_rank(ACCOUNT_ADMIN):
        audit_event("admin_role_authorization", "blocked", user=user, metadata={"reason": "admin_role_required"})
        raise AuthError("Forbidden", 403)
    return user


def role_rank(role: str | None) -> int:
    return ROLE_HIERARCHY.get(str(role or ACCOUNT_CUSTOMER).strip().casefold(), -1)


def role_label(role: str | None) -> str:
    return {
        ACCOUNT_ROOT_ADMIN: "Root admin",
        ACCOUNT_ADMIN: "Admin",
        ACCOUNT_STAFF: "Bank staff",
        ACCOUNT_CUSTOMER: "Normal user",
    }.get(str(role or "").strip().casefold(), "Unknown")


def admin_navigation_for(user: User) -> list[dict[str, str]]:
    items = [
        {"label": "Dashboard", "href": url_for("admin.index"), "endpoint": "admin.index", "group": "overview"},
    ]
    if user.account_type == ACCOUNT_STAFF:
        items.append(
            {
                "label": "Business operations",
                "href": url_for("admin.index"),
                "endpoint": "admin.index",
                "group": "business",
            }
        )
        return items
    if role_rank(user.account_type) >= role_rank(ACCOUNT_ADMIN):
        items.extend(
            [
                {
                    "label": "Audit logs",
                    "href": url_for("admin.audit_logs"),
                    "endpoint": "admin.audit_logs",
                    "group": "security",
                },
                {
                    "label": "Alerts",
                    "href": url_for("admin.alerts"),
                    "endpoint": "admin.alerts",
                    "group": "security",
                },
                {
                    "label": "Staff/admin users",
                    "href": url_for("admin.staff_accounts"),
                    "endpoint": "admin.staff_accounts",
                    "group": "admin",
                },
            ]
        )
    if is_root_admin(user):
        items.extend(
            [
                {
                    "label": "Staff invites",
                    "href": url_for("admin.invites"),
                    "endpoint": "admin.invites",
                    "group": "root",
                },
                {
                    "label": "Manual recovery",
                    "href": url_for("admin.manual_recovery_requests"),
                    "endpoint": "admin.manual_recovery_requests",
                    "group": "root",
                },
            ]
        )
    return items


def admin_dashboard_context(actor: User) -> dict[str, Any]:
    audit_event(
        "admin_dashboard_access",
        "success",
        user=actor,
        metadata={"role": actor.account_type},
    )
    return {
        "user": public_admin_user(actor),
        "role_label": role_label(actor.account_type),
        "navigation": admin_navigation_for(actor),
        "responsibilities": _role_responsibilities(actor),
        "security_notices": _admin_security_notices(actor),
        "summary": _admin_dashboard_summary(actor),
        "recent_audit_events": recent_audit_events_for_dashboard(actor),
    }


def staff_accounts_for_admin(actor: User) -> list[dict[str, Any]]:
    if role_rank(actor.account_type) < role_rank(ACCOUNT_ADMIN):
        audit_event("staff_account_view", "blocked", user=actor, metadata={"reason": "admin_role_required"})
        raise AuthError("Forbidden", 403)
    audit_event(
        "staff_account_view",
        "success",
        user=actor,
        metadata={"role": actor.account_type},
    )
    users = list(
        db.session.execute(
            db.select(User)
            .where(User.account_type.in_(tuple(STAFF_ACCOUNT_TYPES)))
            .order_by(User.account_type.desc(), User.email.asc())
        ).scalars()
    )
    return [public_staff_account(user, actor) for user in users]


def transition_staff_account_as_root_admin(
    actor: User,
    target_user_id: int,
    action: str,
    totp_code: str | None,
) -> dict[str, Any]:
    if not is_root_admin(actor):
        audit_event("staff_account_lifecycle", "blocked", user=actor, metadata={"reason": "not_root_admin"})
        raise AuthError("Forbidden", 403)
    normalized_action = str(action or "").strip().casefold()
    if normalized_action not in {"deactivate", "reactivate", "reset_activation"}:
        audit_event("staff_account_lifecycle", "failure", user=actor, metadata={"reason": "invalid_action"})
        raise AuthError("Invalid staff account action", 400)
    target = db.session.get(User, int(target_user_id))
    if target is not None and target.id == actor.id:
        audit_event(
            "staff_account_lifecycle",
            "blocked",
            user=actor,
            metadata={"reason": "self_management_denied", "action": normalized_action},
        )
        raise AuthError("Forbidden", 403)
    if target is None or target.account_type not in ADMIN_ACCOUNT_MANAGED_TYPES:
        audit_event(
            "staff_account_lifecycle",
            "blocked",
            user=actor,
            metadata={"reason": "target_not_manageable", "action": normalized_action},
        )
        raise AuthError("Staff account not found", 404)
    if not totp_code or not _verify_totp_for_user(actor, totp_code, f"staff_account_{normalized_action}"):
        audit_event(
            "staff_account_lifecycle",
            "failure",
            user=actor,
            metadata={
                "reason": "invalid_totp_step_up",
                "action": normalized_action,
                "target_staff_ref": audit_reference("staff_user", target.id),
            },
        )
        raise AuthError("Fresh MFA verification is required", 403)

    revoked_sessions = 0
    if normalized_action == "deactivate":
        target.account_status = "revoked"
        revoked_sessions = revoke_all_sessions(target.id, ended_reason="revoked")
        event_type = "staff_account_deactivated"
    elif normalized_action == "reactivate":
        if not target.mfa_enabled or target.workplace_email_verified_at is None:
            audit_event(
                "staff_account_reactivated",
                "blocked",
                user=actor,
                metadata={
                    "reason": "activation_prerequisites_missing",
                    "target_staff_ref": audit_reference("staff_user", target.id),
                },
            )
            raise AuthError("Staff account activation requirements are incomplete", 409)
        target.account_status = "active"
        event_type = "staff_account_reactivated"
    else:
        target.account_status = "setup_pending"
        target.mfa_enabled = False
        target.mfa_secret_nonce = None
        target.mfa_secret_ciphertext = None
        target.workplace_email_verified_at = None
        revoked_sessions = revoke_all_sessions(target.id, ended_reason="revoked")
        event_type = "staff_activation_reset"

    audit_event_required(
        event_type,
        "success",
        user=actor,
        metadata={
            "target_staff_ref": audit_reference("staff_user", target.id),
            "target_role": target.account_type,
            "target_status": target.account_status,
            "revoked_sessions": revoked_sessions,
        },
    )
    db.session.commit()
    return {"message": "Staff account updated", "account": public_staff_account(target, actor)}


def recent_audit_events_for_dashboard(actor: User, *, limit: int = 5) -> list[dict[str, Any]]:
    if role_rank(actor.account_type) < role_rank(ACCOUNT_ADMIN):
        return []
    events = list(
        db.session.execute(
            db.select(SecurityAuditEvent).order_by(SecurityAuditEvent.created_at.desc(), SecurityAuditEvent.id.desc()).limit(limit)
        ).scalars()
    )
    return [public_audit_event(event, include_metadata=False) for event in events]


def query_audit_events_for_admin(actor: User, args: dict[str, Any]) -> dict[str, Any]:
    if role_rank(actor.account_type) < role_rank(ACCOUNT_ADMIN):
        audit_event("audit_log_view", "blocked", user=actor, metadata={"reason": "admin_role_required"})
        raise AuthError("Forbidden", 403)
    filters = _audit_filters(args)
    page = _bounded_int(args.get("page"), default=1, minimum=1, maximum=10000)
    per_page = _bounded_int(args.get("per_page"), default=25, minimum=1, maximum=100)
    sort = _validated_choice(args.get("sort"), {"timestamp", "severity", "event_type", "actor"}, "timestamp")
    direction = _validated_choice(args.get("direction"), {"asc", "desc"}, "desc")
    statement = db.select(SecurityAuditEvent)
    statement = _apply_audit_filters(statement, filters)
    total = db.session.execute(db.select(func.count()).select_from(statement.subquery())).scalar_one()
    order_column = {
        "timestamp": SecurityAuditEvent.created_at,
        "severity": cast(SecurityAuditEvent.event_metadata, String),
        "event_type": SecurityAuditEvent.event_type,
        "actor": SecurityAuditEvent.user_id,
    }[sort]
    if direction == "asc":
        statement = statement.order_by(order_column.asc(), SecurityAuditEvent.id.asc())
    else:
        statement = statement.order_by(order_column.desc(), SecurityAuditEvent.id.desc())
    events = list(
        db.session.execute(statement.limit(per_page).offset((page - 1) * per_page)).scalars()
    )
    audit_event(
        "audit_log_view",
        "success",
        user=actor,
        metadata={
            "filters_used": sorted(key for key, value in filters.items() if value not in {None, ""}),
            "sort": sort,
            "direction": direction,
            "page": page,
            "per_page": per_page,
        },
    )
    return {
        "events": [public_audit_event(event, include_metadata=False) for event in events],
        "filters": filters,
        "page": page,
        "per_page": per_page,
        "total": int(total or 0),
        "sort": sort,
        "direction": direction,
    }


def audit_event_detail_for_admin(actor: User, event_id: int) -> dict[str, Any]:
    if role_rank(actor.account_type) < role_rank(ACCOUNT_ADMIN):
        audit_event("audit_log_detail_view", "blocked", user=actor, metadata={"reason": "admin_role_required"})
        raise AuthError("Forbidden", 403)
    event = db.session.get(SecurityAuditEvent, int(event_id))
    if event is None:
        raise AuthError("Audit event not found", 404)
    audit_event(
        "audit_log_detail_view",
        "success",
        user=actor,
        metadata={"audit_event_ref": audit_reference("security_audit_event", event.id)},
    )
    return public_audit_event(event, include_metadata=True)


def public_staff_account(user: User, actor: User) -> dict[str, Any]:
    return {
        "id": user.id,
        "name": user.full_name,
        "workplace_email": user.email,
        "role": user.account_type,
        "role_label": role_label(user.account_type),
        "account_status": user.account_status,
        "totp_enrolled": bool(user.mfa_enabled),
        "workplace_email_verified": bool(user.workplace_email_verified_at),
        "created_at": _utc_iso(user.created_at),
        "last_login_at": _utc_iso(user.last_login_at) if user.last_login_at else None,
        "can_manage": bool(is_root_admin(actor) and user.account_type in ADMIN_ACCOUNT_MANAGED_TYPES and user.id != actor.id),
    }


def public_audit_event(event: SecurityAuditEvent, *, include_metadata: bool) -> dict[str, Any]:
    payload = {
        "id": event.id,
        "event_type": event.event_type,
        "outcome": event.outcome,
        "actor_user_id": event.user_id,
        "ip_address": event.ip_address,
        "correlation_id": event.correlation_id,
        "session_ref": event.session_ref,
        "created_at": _utc_iso(event.created_at),
    }
    metadata = event.event_metadata if isinstance(event.event_metadata, dict) else {}
    payload["severity"] = str(metadata.get("severity") or "").strip()[:24] if metadata else ""
    if include_metadata:
        payload["metadata"] = _safe_metadata_for_display(metadata)
    return payload


def _role_responsibilities(actor: User) -> list[str]:
    if is_root_admin(actor):
        return [
            "Invite and revoke staff/admin onboarding records",
            "Manage staff/admin account lifecycle state",
            "Review audit, alert, and high-risk security events",
        ]
    if actor.account_type == ACCOUNT_ADMIN:
        return [
            "Review audit logs and security alerts",
            "Monitor staff/admin account status with safe metadata",
            "Handle technical security workflows without customer fund access",
        ]
    return [
        "Use assigned business-operation tools only",
        "Escalate suspicious or sensitive customer cases",
        "No technical staff/admin management permissions",
    ]


def _admin_security_notices(actor: User) -> list[dict[str, str]]:
    notices = [
        {
            "severity": "info",
            "title": "Authenticator MFA required",
            "message": "Staff/admin access uses workplace login plus TOTP; passkeys and WebAuthn are not offered in this workflow.",
        },
        {
            "severity": "warning",
            "title": "Separation of duties",
            "message": "Privileged admin tools must not be used against the actor's own customer identity.",
        },
    ]
    if not actor.mfa_enabled:
        notices.insert(
            0,
            {
                "severity": "danger",
                "title": "TOTP not enrolled",
                "message": "This staff/admin account cannot complete normal admin access until TOTP is enrolled.",
            },
        )
    if is_root_admin(actor):
        pending_invites = db.session.execute(
            db.select(func.count())
            .select_from(StaffInvite)
            .where(StaffInvite.status.in_(tuple(ACTIVE_INVITE_STATUSES)))
        ).scalar_one()
        if int(pending_invites or 0) > 0:
            notices.append(
                {
                    "severity": "warning",
                    "title": "Pending staff invites",
                    "message": f"{int(pending_invites)} staff/admin invite(s) are pending review.",
                }
            )
    return notices


def _admin_dashboard_summary(actor: User) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "current_role_rank": role_rank(actor.account_type),
        "totp_enrolled": bool(actor.mfa_enabled),
        "workplace_email_verified": bool(actor.workplace_email_verified_at),
        "account_status": actor.account_status,
        "pending_invites": None,
        "staff_accounts": None,
        "active_alerts": None,
    }
    if is_root_admin(actor):
        summary["pending_invites"] = int(
            db.session.execute(
                db.select(func.count())
                .select_from(StaffInvite)
                .where(StaffInvite.status.in_(tuple(ACTIVE_INVITE_STATUSES)))
            ).scalar_one()
            or 0
        )
    if role_rank(actor.account_type) >= role_rank(ACCOUNT_ADMIN):
        rows = db.session.execute(
            db.select(User.account_type, User.account_status, func.count())
            .where(User.account_type.in_(tuple(STAFF_ACCOUNT_TYPES)))
            .group_by(User.account_type, User.account_status)
        ).all()
        summary["staff_accounts"] = [
            {"role": role, "status": status, "count": int(count)}
            for role, status, count in rows
        ]
    return summary


def _audit_filters(args: dict[str, Any]) -> dict[str, str]:
    return {
        "event_type": _safe_filter(args.get("event_type"), 80),
        "actor": _safe_filter(args.get("actor"), 32),
        "target": _safe_filter(args.get("target"), 80),
        "role": _validated_choice(args.get("role"), STAFF_ACCOUNT_TYPES | {ACCOUNT_CUSTOMER}, ""),
        "severity": _validated_choice(args.get("severity"), {"low", "medium", "high", "critical"}, ""),
        "outcome": _safe_filter(args.get("outcome") or args.get("status"), 24),
        "ip_address": _safe_filter(args.get("ip_address"), 64),
        "request_id": _safe_filter(args.get("request_id") or args.get("correlation_id"), 64),
        "from": _safe_filter(args.get("from"), 40),
        "to": _safe_filter(args.get("to"), 40),
        "q": _safe_filter(args.get("q"), 80),
    }


def _apply_audit_filters(statement, filters: dict[str, str]):
    if filters["event_type"]:
        statement = statement.where(SecurityAuditEvent.event_type == filters["event_type"])
    if filters["outcome"]:
        statement = statement.where(SecurityAuditEvent.outcome == filters["outcome"])
    if filters["actor"]:
        try:
            actor_id = int(filters["actor"])
        except ValueError:
            actor_id = None
        if actor_id is not None:
            statement = statement.where(SecurityAuditEvent.user_id == actor_id)
    if filters["role"]:
        statement = statement.join(User, User.id == SecurityAuditEvent.user_id).where(
            User.account_type == filters["role"]
        )
    if filters["ip_address"]:
        statement = statement.where(SecurityAuditEvent.ip_address == filters["ip_address"])
    if filters["request_id"]:
        statement = statement.where(SecurityAuditEvent.correlation_id == filters["request_id"])
    since = _parse_filter_datetime(filters["from"])
    until = _parse_filter_datetime(filters["to"])
    if since is not None:
        statement = statement.where(SecurityAuditEvent.created_at >= since)
    if until is not None:
        statement = statement.where(SecurityAuditEvent.created_at <= until)
    metadata_text = cast(SecurityAuditEvent.event_metadata, String)
    if filters["severity"]:
        statement = statement.where(metadata_text.ilike(f"%severity%{filters['severity']}%"))
    if filters["target"]:
        statement = statement.where(metadata_text.ilike(f"%{_like_escape(filters['target'])}%", escape="\\"))
    if filters["q"]:
        pattern = f"%{_like_escape(filters['q'])}%"
        statement = statement.where(
            or_(
                SecurityAuditEvent.event_type.ilike(pattern, escape="\\"),
                SecurityAuditEvent.outcome.ilike(pattern, escape="\\"),
                SecurityAuditEvent.correlation_id.ilike(pattern, escape="\\"),
                metadata_text.ilike(pattern, escape="\\"),
            )
        )
    return statement


def _safe_metadata_for_display(metadata: dict[str, Any]) -> dict[str, Any]:
    allowed: dict[str, Any] = {}
    for key, value in list(metadata.items())[:30]:
        key_text = _safe_filter(key, 64)
        if not key_text or _display_key_is_sensitive(key_text):
            continue
        if isinstance(value, bool | int | float) or value is None:
            allowed[key_text] = value
            continue
        if isinstance(value, list | tuple):
            allowed[key_text] = [_safe_filter(item, 120) for item in list(value)[:10]]
            continue
        if isinstance(value, dict):
            allowed[key_text] = {
                _safe_filter(nested_key, 64): _safe_filter(nested_value, 120)
                for nested_key, nested_value in list(value.items())[:10]
                if _safe_filter(nested_key, 64)
                and not _display_key_is_sensitive(_safe_filter(nested_key, 64))
            }
            continue
        allowed[key_text] = _safe_filter(value, 160)
    return allowed


def _display_key_is_sensitive(key: str) -> bool:
    lowered = key.casefold().replace("-", "_")
    if lowered.endswith("_ref") or lowered in {"principal_ref", "session_ref"}:
        return False
    return any(
        part in lowered
        for part in (
            "authorization",
            "ciphertext",
            "cookie",
            "csrf",
            "hmac",
            "kek",
            "mfa_secret",
            "nonce",
            "password",
            "private_key",
            "recovery_code",
            "secret",
            "session_id",
            "token",
            "totp",
            "url",
        )
    )


def _safe_filter(value: Any, limit: int) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    cleaned = "".join(char if (char >= " " and char != "\x7f") else " " for char in text)
    return " ".join(cleaned.split())[:limit]


def _validated_choice(value: Any, allowed: set[str] | frozenset[str], default: str) -> str:
    text = str(value or "").strip().casefold()
    return text if text in allowed else default


def _bounded_int(value: Any, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return min(max(parsed, minimum), maximum)


def _parse_filter_datetime(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return _as_utc(parsed)


def _like_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def authenticate_admin_primary(workplace_email: str, password: str) -> dict[str, Any]:
    normalized_email = normalize_workplace_email(workplace_email)
    principal = _auth_principal(normalized_email)
    try:
        _enforce_auth_backoff("admin_login", principal)
    except AuthError:
        raise

    user = _staff_user_by_workplace_email(normalized_email)
    password_ok = False
    if is_password_raw_length_safe(password):
        candidate_hash = user.password_hash if user else _dummy_password_hash()
        password_ok = verify_password(password, candidate_hash)

    if (
        user is None
        or not password_ok
        or not is_active_staff_user(user)
        or not user.workplace_email_verified_at
    ):
        audit_event(
            "admin_login",
            "failure",
            user=user,
            metadata={
                "known_user": user is not None,
                "principal_ref": principal_reference(normalized_email),
            },
        )
        record_failure("admin_login", principal)
        raise AuthError(GENERIC_ADMIN_LOGIN_ERROR, 401)

    if user.is_frozen or user.security_locked_at is not None:
        audit_event("admin_login", "blocked", user=user, metadata={"reason": user.security_lock_reason or "locked"})
        raise AuthError(GENERIC_ADMIN_LOGIN_ERROR, 401)

    user.failed_login_count = 0
    user.last_login_at = _utcnow()
    if password_hash_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    db.session.commit()
    clear_failures("admin_login", principal)
    begin_password_authenticated_session(user.id)
    audit_event("admin_login_password", "success", user=user, metadata={"mfa_required": True})
    return {"message": "MFA verification required", "mfa_required": True}


def complete_admin_mfa_login(totp_code: str) -> dict[str, Any]:
    user_id = session.get("pending_mfa_user_id")
    if not user_id:
        raise AuthError("No pending MFA challenge", 401)
    user = db.session.get(User, int(user_id))
    if not is_active_staff_user(user):
        audit_event("admin_mfa_login", "failure", user_id=int(user_id), metadata={"reason": "not_active_staff"})
        raise AuthError("No pending MFA challenge", 401)
    if not _verify_totp_for_user(user, totp_code, "admin_mfa_login"):
        audit_event("admin_mfa_login", "failure", user=user)
        raise AuthError(GENERIC_ADMIN_LOGIN_ERROR, 401)
    session_id = establish_authenticated_session(
        user_id=user.id,
        mfa_verified=True,
        auth_context="admin_password+totp",
    )
    audit_event("admin_mfa_login", "success", user=user, session_id=session_id)
    return {
        "message": "Login successful",
        "session_ref": public_session_reference(session_id),
        "user": public_admin_user(user),
    }


def logout_admin_session() -> None:
    user_id = session.get("user_id") or session.get("pending_mfa_user_id")
    revoke_current_session(ended_reason="logout")
    audit_event("admin_logout", "success", user_id=int(user_id) if user_id else None)


def create_staff_invite(
    actor: User,
    *,
    personal_email: str,
    workplace_email: str,
    role: str,
    totp_code: str | None,
) -> dict[str, Any]:
    if not is_root_admin(actor):
        audit_event("staff_invite_create", "blocked", user=actor, metadata={"reason": "not_root_admin"})
        raise AuthError("Forbidden", 403)
    if not totp_code:
        audit_event("staff_invite_create", "failure", user=actor, metadata={"reason": "missing_totp_step_up"})
        raise AuthError("Fresh MFA verification is required", 403)

    normalized_personal = normalize_personal_email(personal_email)
    normalized_workplace = normalize_workplace_email(workplace_email)
    normalized_role = str(role or "").strip().casefold()
    if normalized_role not in INVITABLE_ROLES:
        audit_event("staff_invite_create", "failure", user=actor, metadata={"reason": "invalid_role"})
        raise AuthError("Invalid invite role", 400)
    if normalized_role == ACCOUNT_ROOT_ADMIN:
        raise AuthError("Invalid invite role", 400)
    _reject_existing_staff_identity(normalized_workplace)
    _reject_active_invite(normalized_workplace, normalized_personal)
    if not _verify_totp_for_user(actor, totp_code, "staff_invite_create"):
        audit_event("staff_invite_create", "failure", user=actor, metadata={"reason": "invalid_totp_step_up"})
        raise AuthError("Fresh MFA verification is required", 403)

    token = secrets.token_urlsafe(32)
    now = _utcnow()
    invite = StaffInvite(
        token_hash=invite_token_hash(token),
        personal_email_normalized=normalized_personal,
        workplace_email_normalized=normalized_workplace,
        role=normalized_role,
        status="pending",
        created_by_user_id=actor.id,
        created_at=now,
        expires_at=now + timedelta(seconds=int(current_app.config["STAFF_INVITE_TTL_SECONDS"])),
    )
    db.session.add(invite)
    try:
        db.session.flush()
        audit_event_required(
            "staff_invite_created",
            "success",
            user=actor,
            metadata=_invite_audit_metadata(invite),
        )
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        audit_event("staff_invite_create", "failure", user=actor, metadata={"reason": "integrity_error"})
        raise AuthError("Invite could not be created", 400) from exc

    invite_url = url_for("admin.invite_accept_info", token=token, _external=True)
    try:
        _send_invite_email(invite, invite_url)
    except Exception as exc:
        current_app.logger.warning("staff_invite_email_failed error=%s", type(exc).__name__)
        audit_event(
            "staff_invite_email",
            "failure",
            user=actor,
            metadata={**_invite_audit_metadata(invite), "reason": "email_delivery_failed"},
        )
        raise AuthError("Invite could not be sent", 503) from exc
    audit_event("staff_invite_email", "queued", user=actor, metadata=_invite_audit_metadata(invite))
    return {
        "message": "Invite created",
        "invite": public_invite(invite),
    }


def public_invites_for_root_admin() -> list[dict[str, Any]]:
    invites = list(
        db.session.execute(
            db.select(StaffInvite).order_by(StaffInvite.created_at.desc(), StaffInvite.id.desc())
        ).scalars()
    )
    return [public_invite(invite) for invite in invites]


def revoke_staff_invite(actor: User, invite_id: int, totp_code: str | None) -> dict[str, Any]:
    if not is_root_admin(actor):
        raise AuthError("Forbidden", 403)
    if not totp_code or not _verify_totp_for_user(actor, totp_code, "staff_invite_revoke"):
        audit_event("staff_invite_revoked", "failure", user=actor, metadata={"reason": "invalid_totp_step_up"})
        raise AuthError("Fresh MFA verification is required", 403)
    invite = db.session.get(StaffInvite, int(invite_id))
    if invite is None or invite.status not in ACTIVE_INVITE_STATUSES:
        raise AuthError("Invite not found", 404)
    invite.status = "revoked"
    invite.revoked_at = _utcnow()
    invite.revoked_by_user_id = actor.id
    audit_event_required("staff_invite_revoked", "success", user=actor, metadata=_invite_audit_metadata(invite))
    db.session.commit()
    return {"message": "Invite revoked", "invite": public_invite(invite)}


def manual_recovery_requests_for_admin(actor: User) -> list[dict[str, Any]]:
    if not is_root_admin(actor):
        audit_event("manual_recovery_admin_review", "blocked", user=actor, metadata={"reason": "not_root_admin"})
        raise AuthError("Forbidden", 403)
    requests = list(
        db.session.execute(
            db.select(ManualRecoveryRequest).order_by(
                ManualRecoveryRequest.created_at.desc(),
                ManualRecoveryRequest.id.desc(),
            )
        ).scalars()
    )
    return [public_manual_recovery_request(item) for item in requests]


def transition_manual_recovery_request_as_admin(
    actor: User,
    request_id: int,
    status: str,
    reason: str,
    totp_code: str | None,
) -> dict[str, Any]:
    if not is_root_admin(actor):
        audit_event("manual_recovery_admin_transition", "blocked", user=actor, metadata={"reason": "not_root_admin"})
        raise AuthError("Forbidden", 403)
    normalized_status = str(status or "").strip().casefold()
    if normalized_status not in MANUAL_RECOVERY_ADMIN_TRANSITION_STATUSES:
        audit_event(
            "manual_recovery_admin_transition",
            "failure",
            user=actor,
            metadata={"reason": "invalid_status"},
        )
        raise AuthError("Invalid manual recovery status", 400)
    clean_reason = _require_manual_recovery_reason(reason, "manual_recovery_admin_transition", actor)
    scope = f"manual_recovery_transition_{normalized_status}"
    if not totp_code or not _verify_totp_for_user(actor, totp_code, scope):
        audit_event(
            "manual_recovery_admin_transition",
            "failure",
            user=actor,
            metadata={"reason": "invalid_totp_step_up"},
        )
        raise AuthError("Fresh MFA verification is required", 403)

    result = transition_manual_recovery_request(request_id, normalized_status, reason=clean_reason)
    audit_event(
        "manual_recovery_admin_transition",
        "success",
        user=actor,
        metadata={
            "request_ref": audit_reference("manual_recovery_request", request_id),
            "new_status": result["status"],
            "reason_recorded": True,
        },
    )
    return {"message": "Manual recovery request updated", "request": result}


def complete_manual_recovery_request_as_admin(
    actor: User,
    request_id: int,
    reason: str,
    totp_code: str | None,
) -> dict[str, Any]:
    if not is_root_admin(actor):
        audit_event("manual_recovery_admin_complete", "blocked", user=actor, metadata={"reason": "not_root_admin"})
        raise AuthError("Forbidden", 403)
    clean_reason = _require_manual_recovery_reason(reason, "manual_recovery_admin_complete", actor)
    if not totp_code or not _verify_totp_for_user(actor, totp_code, "manual_recovery_complete"):
        audit_event(
            "manual_recovery_admin_complete",
            "failure",
            user=actor,
            metadata={"reason": "invalid_totp_step_up"},
        )
        raise AuthError("Fresh MFA verification is required", 403)

    result = complete_manual_recovery_request(request_id, reason=clean_reason)
    audit_event(
        "manual_recovery_admin_complete",
        "success",
        user=actor,
        metadata={
            "request_ref": audit_reference("manual_recovery_request", request_id),
            "mfa_reenrollment_required": bool(result.get("mfa_reenrollment_required")),
            "revoked_sessions": int(result.get("revoked_sessions") or 0),
        },
    )
    return {"message": "Manual recovery request completed", "request": result}


def invite_info(token: str) -> dict[str, Any]:
    invite = _active_invite_by_token(token, audit_failures=True)
    return {
        "message": "Invite found",
        "invite": {
            "workplace_email": invite.workplace_email_normalized,
            "role": invite.role,
            "expires_at": _utc_iso(invite.expires_at),
            "status": invite.status,
        },
    }


def start_invite_acceptance(
    token: str,
    *,
    full_name: str,
    phone_number: str,
    password: str,
    confirm_password: str,
    turnstile_token: str | None,
    request_fields: set[str],
) -> dict[str, Any]:
    _reject_forged_invite_fields(request_fields)
    try:
        verify_turnstile_token(turnstile_token)
    except TurnstileError as exc:
        audit_event("staff_invite_accept", "failure", metadata={"reason": "turnstile_failed"})
        raise AuthError("Invite acceptance failed", 400) from exc

    invite = _active_invite_by_token(token, lock=True, audit_failures=True)
    name = validate_full_name(full_name)
    phone = validate_phone_number(phone_number)
    if password != confirm_password:
        audit_event("staff_invite_accept", "failure", metadata={"reason": "password_mismatch"})
        raise AuthError("Passwords must match", 400)
    try:
        validate_password_policy(password)
    except PasswordPolicyError as exc:
        audit_event("staff_invite_accept", "failure", metadata={"reason": "password_policy"})
        raise AuthError(str(exc), 400) from exc

    user = db.session.get(User, invite.setup_user_id) if invite.setup_user_id else None
    if user is None:
        _reject_duplicate_staff_signup(invite.workplace_email_normalized, phone)
        user = User(
            username=_staff_username(invite.workplace_email_normalized),
            email=invite.workplace_email_normalized,
            password_hash=hash_password(password),
            account_type=invite.role,
            account_status="setup_pending",
            full_name=name,
            phone_number=phone,
            account_number=None,
            staff_personal_email=invite.personal_email_normalized,
            mfa_enabled=False,
        )
        db.session.add(user)
        db.session.flush()
        invite.setup_user_id = user.id
    else:
        if user.account_status != "setup_pending" or user.account_type != invite.role:
            raise AuthError(GENERIC_INVITE_ERROR, 401)
        user.full_name = name
        user.phone_number = phone
        user.password_hash = hash_password(password)
        user.staff_personal_email = invite.personal_email_normalized

    secret = pyotp.random_base32(length=32)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(secret, user.id)
    user.mfa_enabled = False
    invite.status = "totp_pending"
    invite.last_attempt_at = _utcnow()
    try:
        _send_workplace_verification(invite)
        audit_event_required(
            "staff_workplace_verification_sent",
            "queued",
            user=user,
            metadata=_invite_audit_metadata(invite),
        )
        audit_event_required(
            "staff_invite_accept_started",
            "success",
            user=user,
            metadata=_invite_audit_metadata(invite),
        )
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        current_app.logger.warning("staff_workplace_verification_email_failed error=%s", type(exc).__name__)
        audit_event("staff_workplace_verification_sent", "failure", metadata={"reason": "email_delivery_failed"})
        raise AuthError("Invite acceptance failed", 503) from exc
    return {
        "message": "TOTP setup required",
        "invite": {
            "workplace_email": invite.workplace_email_normalized,
            "role": invite.role,
        },
        "totp_setup": _mfa_setup_payload(user, secret),
        "workplace_verification_required": True,
    }


def verify_invite_acceptance(
    token: str,
    *,
    totp_code: str,
    workplace_verification_code: str,
    request_fields: set[str],
) -> dict[str, Any]:
    _reject_forged_invite_fields(request_fields)
    invite = _active_invite_by_token(token, lock=True, audit_failures=True)
    user = db.session.get(User, invite.setup_user_id) if invite.setup_user_id else None
    if user is None or user.account_status != "setup_pending" or user.account_type != invite.role:
        audit_event("staff_invite_accept", "failure", metadata={"reason": "setup_missing"})
        raise AuthError(GENERIC_INVITE_ERROR, 401)
    if not TOTP_RE.fullmatch(str(totp_code or "")):
        audit_event("staff_totp_setup", "failure", user=user, metadata={"reason": "invalid_format"})
        raise AuthError("Invalid authentication code.", 401)
    if not _verify_totp_for_user(user, totp_code, "staff_totp_setup"):
        audit_event("staff_totp_setup", "failure", user=user)
        raise AuthError("Invalid authentication code.", 401)
    if not _verify_workplace_code(invite, workplace_verification_code):
        audit_event(
            "staff_workplace_verification",
            "failure",
            user=user,
            metadata=_invite_audit_metadata(invite),
        )
        raise AuthError(GENERIC_WORKPLACE_VERIFICATION_ERROR, 401)

    now = _utcnow()
    user.mfa_enabled = True
    user.account_status = "active"
    user.workplace_email_verified_at = now
    invite.status = "accepted"
    invite.used_at = now
    invite.used_by_user_id = user.id
    invite.workplace_verified_at = now
    audit_event_required("staff_totp_setup", "success", user=user, metadata={"method": "totp"})
    audit_event_required("staff_workplace_verification", "success", user=user, metadata=_invite_audit_metadata(invite))
    audit_event_required("staff_account_activated", "success", user=user, metadata=_invite_audit_metadata(invite))
    db.session.commit()
    return {
        "message": "Staff account activated",
        "user": public_admin_user(user),
    }


def public_admin_user(user: User) -> dict[str, Any]:
    return {
        "id": user.id,
        "email": user.email,
        "account_type": user.account_type,
        "account_status": user.account_status,
        "mfa_enabled": user.mfa_enabled,
        "workplace_email_verified": bool(user.workplace_email_verified_at),
    }


def public_invite(invite: StaffInvite) -> dict[str, Any]:
    return {
        "id": invite.id,
        "personal_email_ref": audit_reference("staff_personal_email", invite.personal_email_normalized),
        "workplace_email": invite.workplace_email_normalized,
        "role": invite.role,
        "status": invite.status,
        "created_at": _utc_iso(invite.created_at),
        "expires_at": _utc_iso(invite.expires_at),
        "used_at": _utc_iso(invite.used_at) if invite.used_at else None,
        "revoked_at": _utc_iso(invite.revoked_at) if invite.revoked_at else None,
    }


def public_manual_recovery_request(request_record: ManualRecoveryRequest) -> dict[str, Any]:
    return {
        "id": request_record.id,
        "status": request_record.status,
        "active": request_record.status in MANUAL_RECOVERY_ACTIVE_STATUSES,
        "request_count": int(request_record.request_count or 0),
        "created_at": _utc_iso(request_record.created_at),
        "updated_at": _utc_iso(request_record.updated_at),
        "expires_at": _utc_iso(request_record.expires_at),
        "completed": request_record.completed_at is not None,
        "completed_at": _utc_iso(request_record.completed_at) if request_record.completed_at else None,
        "linked_customer": request_record.user_id is not None,
    }


def normalize_workplace_email(email: str) -> str:
    normalized = _normalize_email(email)
    local, separator, domain = normalized.partition("@")
    if not _valid_email_parts(local, separator, domain):
        raise AuthError("Invalid workplace email", 400)
    if domain.casefold() not in _workplace_domains():
        raise AuthError("Invalid workplace email", 400)
    if _contains_alias_separator(local):
        raise AuthError("Invalid workplace email", 400)
    return f"{local}@{domain.casefold()}"


def normalize_personal_email(email: str) -> str:
    normalized = _normalize_email(email)
    local, separator, domain = normalized.partition("@")
    if not _valid_email_parts(local, separator, domain):
        raise AuthError("Invalid personal email", 400)
    domain_lower = domain.casefold()
    if domain_lower in _workplace_domains() or domain_lower not in _personal_domains():
        raise AuthError("Invalid personal email", 400)
    if _contains_alias_separator(local):
        raise AuthError("Invalid personal email", 400)
    return f"{local}@{domain_lower}"


def validate_full_name(full_name: str) -> str:
    text = str(full_name or "").strip()
    if not FULL_NAME_RE.fullmatch(text):
        raise AuthError("Invalid full name", 400)
    return text


def validate_phone_number(phone_number: str) -> str:
    text = str(phone_number or "").strip()
    if not PHONE_RE.fullmatch(text):
        raise AuthError("Invalid phone number", 400)
    return text


def invite_token_hash(token: str) -> str:
    token_text = str(token or "").strip()
    if len(token_text) < 32 or not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", token_text):
        raise AuthError(GENERIC_INVITE_ERROR, 401)
    return active_hmac_hex(f"staff-invite-token:{token_text}", length=64)


def _active_invite_by_token(
    token: str,
    *,
    lock: bool = False,
    audit_failures: bool = False,
) -> StaffInvite:
    try:
        token_hash = invite_token_hash(token)
    except AuthError:
        if audit_failures:
            audit_event("staff_invite_invalid_attempt", "failure", metadata={"reason": "malformed_token"})
        raise
    statement = db.select(StaffInvite).where(StaffInvite.token_hash == token_hash)
    if lock and db.engine.dialect.name == "postgresql":
        statement = statement.with_for_update()
    invite = db.session.execute(statement).scalar_one_or_none()
    now = _utcnow()
    if invite is None:
        if audit_failures:
            audit_event("staff_invite_invalid_attempt", "failure", metadata={"reason": "missing"})
        raise AuthError(GENERIC_INVITE_ERROR, 401)
    invite.last_attempt_at = now
    if _as_utc(invite.expires_at) <= now:
        invite.status = "expired"
        db.session.commit()
        audit_event("staff_invite_expired", "expired", metadata=_invite_audit_metadata(invite))
        raise AuthError(GENERIC_INVITE_ERROR, 401)
    if invite.revoked_at is not None or invite.status == "revoked":
        if audit_failures:
            audit_event("staff_invite_invalid_attempt", "failure", metadata={"reason": "revoked"})
        raise AuthError(GENERIC_INVITE_ERROR, 401)
    if invite.used_at is not None or invite.status == "accepted":
        if audit_failures:
            audit_event("staff_invite_invalid_attempt", "failure", metadata={"reason": "used"})
        raise AuthError(GENERIC_INVITE_ERROR, 401)
    if invite.status not in ACTIVE_INVITE_STATUSES:
        raise AuthError(GENERIC_INVITE_ERROR, 401)
    return invite


def _send_invite_email(invite: StaffInvite, invite_url: str) -> None:
    send_security_email(
        invite.personal_email_normalized,
        "SITBank staff access invite",
        (
            "You have been invited to set up separate SITBank staff access.\n\n"
            f"Open this link to continue: {invite_url}\n\n"
            "This invite expires in 24 hours. You will set your own password and "
            "must enroll an authenticator app before staff access is activated. "
            "This staff identity is separate from any customer banking account."
        ),
    )


def _send_workplace_verification(invite: StaffInvite) -> None:
    code = f"{secrets.randbelow(1_000_000):06d}"
    now = _utcnow()
    invite.workplace_verification_code_hmac = _workplace_code_hmac(invite, code)
    invite.workplace_verification_sent_at = now
    invite.workplace_verification_expires_at = now + timedelta(
        seconds=int(current_app.config["STAFF_WORKPLACE_VERIFICATION_TTL_SECONDS"])
    )
    send_security_email(
        invite.workplace_email_normalized,
        "SITBank workplace email verification code",
        (
            "Use this code to verify your SITBank workplace email for staff access:\n\n"
            f"{code}\n\n"
            "This code expires shortly. Staff access is separate from customer banking access."
        ),
    )


def _verify_workplace_code(invite: StaffInvite, code: str) -> bool:
    code_text = str(code or "").strip()
    if not WORKPLACE_CODE_RE.fullmatch(code_text):
        return False
    if not invite.workplace_verification_code_hmac or not invite.workplace_verification_expires_at:
        return False
    if _as_utc(invite.workplace_verification_expires_at) <= _utcnow():
        return False
    expected = invite.workplace_verification_code_hmac
    submitted = _workplace_code_hmac(invite, code_text)
    return hmac.compare_digest(expected, submitted)


def _workplace_code_hmac(invite: StaffInvite, code: str) -> str:
    return active_hmac_hex(
        f"staff-workplace-verification:{invite.token_hash}:{invite.workplace_email_normalized}:{code}",
        length=64,
    )


def _reject_forged_invite_fields(request_fields: set[str]) -> None:
    forbidden = {"role", "workplace_email", "email", "account_type", "customer_user_id", "is_admin"}
    forged = sorted(forbidden & {field.strip() for field in request_fields})
    if forged:
        audit_event("staff_invite_accept", "failure", metadata={"reason": "forged_fields", "fields": forged})
        raise AuthError("Invalid request", 400)


def _require_manual_recovery_reason(reason: str, event_type: str, actor: User) -> str:
    text = str(reason or "").strip()
    if not text:
        audit_event(event_type, "failure", user=actor, metadata={"reason": "missing_reason"})
        raise AuthError("Reason is required", 400)
    if len(text) > 512:
        audit_event(event_type, "failure", user=actor, metadata={"reason": "reason_too_long"})
        raise AuthError("Reason is too long", 400)
    return text


def _reject_existing_staff_identity(workplace_email: str) -> None:
    existing = db.session.execute(
        db.select(User).where(
            func.lower(User.email) == workplace_email.casefold(),
            User.account_type.in_(tuple(STAFF_ACCOUNT_TYPES)),
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise AuthError("Invite could not be created", 400)


def _reject_duplicate_staff_signup(workplace_email: str, phone_number: str) -> None:
    existing = db.session.execute(
        db.select(User).where(
            or_(
                func.lower(User.email) == workplace_email.casefold(),
                User.phone_number == phone_number,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise AuthError("Invite acceptance failed", 400)


def _reject_active_invite(workplace_email: str, personal_email: str) -> None:
    now = _utcnow()
    existing = db.session.execute(
        db.select(StaffInvite).where(
            StaffInvite.status.in_(tuple(ACTIVE_INVITE_STATUSES)),
            StaffInvite.revoked_at.is_(None),
            StaffInvite.used_at.is_(None),
            StaffInvite.expires_at > now,
            or_(
                func.lower(StaffInvite.workplace_email_normalized) == workplace_email.casefold(),
                func.lower(StaffInvite.personal_email_normalized) == personal_email.casefold(),
            ),
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise AuthError("Invite could not be created", 400)


def _staff_user_by_workplace_email(email: str) -> User | None:
    return db.session.execute(
        db.select(User).where(
            func.lower(User.email) == email.casefold(),
            User.account_type.in_(tuple(STAFF_ACCOUNT_TYPES)),
        )
    ).scalar_one_or_none()


def _staff_username(workplace_email: str) -> str:
    local = workplace_email.partition("@")[0]
    normalized = re.sub(r"[^A-Za-z0-9_.-]", ".", local).strip(".")[:48] or "staff"
    base = f"staff.{normalized}"
    if len(base) < 3:
        base = "staff.user"
    candidate = base[:64]
    suffix = 0
    while db.session.execute(db.select(User.id).where(func.lower(User.username) == candidate.casefold())).scalar_one_or_none():
        suffix += 1
        candidate = f"{base[:56]}.{suffix:02d}"
    if not STAFF_USERNAME_RE.fullmatch(candidate):
        return f"staff.{secrets.token_hex(8)}"
    return candidate


def _mfa_setup_payload(user: User, secret: str) -> dict[str, str]:
    provisioning_uri = pyotp.TOTP(secret, digits=6, interval=30, digest=hashlib.sha1).provisioning_uri(
        name=user.email,
        issuer_name=current_app.config["MFA_ISSUER_NAME"],
    )
    return {
        "issuer": current_app.config["MFA_ISSUER_NAME"],
        "manual_entry_secret": secret,
        "otpauth_uri": provisioning_uri,
        "qr_code_data_uri": _qr_data_uri(provisioning_uri),
    }


def _qr_data_uri(provisioning_uri: str) -> str:
    import base64
    import io

    import qrcode

    image = qrcode.make(provisioning_uri)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def _invite_audit_metadata(invite: StaffInvite) -> dict[str, Any]:
    return {
        "invite_ref": audit_reference("staff_invite", invite.id),
        "workplace_email_ref": audit_reference("staff_workplace_email", invite.workplace_email_normalized),
        "personal_email_ref": audit_reference("staff_personal_email", invite.personal_email_normalized),
        "target_role": invite.role,
        "status": invite.status,
    }


def _auth_principal(identifier: str) -> str:
    return f"{request.remote_addr or 'unknown'}:{_normalize_email(identifier).casefold()}"


def _enforce_auth_backoff(scope: str, principal: str) -> None:
    try:
        apply_exponential_backoff(scope, principal)
    except AuthBackoffRequired as exc:
        audit_event("auth_backoff", "blocked", metadata={"scope": scope, "retry_after": exc.retry_after})
        raise AuthError(ADMIN_AUTH_BACKOFF_ERROR, 429, retry_after=exc.retry_after) from exc


def _normalize_email(email: str) -> str:
    text = str(email or "").strip()
    if "\x00" in text or "\r" in text or "\n" in text or len(text) > 255:
        raise AuthError("Invalid email", 400)
    local, separator, domain = text.partition("@")
    return f"{local}@{domain.strip().casefold()}" if separator else text


def _valid_email_parts(local: str, separator: str, domain: str) -> bool:
    if separator != "@" or not local or not domain:
        return False
    if not EMAIL_RE.fullmatch(f"{local}@{domain}"):
        return False
    labels = domain.split(".")
    return all(label and not label.startswith("-") and not label.endswith("-") for label in labels)


def _contains_alias_separator(local: str) -> bool:
    separators = tuple(current_app.config.get("STAFF_INVITE_ALIAS_SEPARATORS") or ("+",))
    return any(separator and separator in local for separator in separators)


def _workplace_domains() -> frozenset[str]:
    return frozenset(str(item).casefold() for item in current_app.config["SIT_WORKPLACE_EMAIL_DOMAINS"])


def _personal_domains() -> frozenset[str]:
    return frozenset(str(item).casefold() for item in current_app.config["STAFF_INVITE_PERSONAL_EMAIL_DOMAINS"])


def _root_admin_emails() -> frozenset[str]:
    return frozenset(str(item).casefold() for item in current_app.config["ROOT_ADMIN_EMAILS"])


def _utcnow() -> datetime:
    return datetime.fromtimestamp(time.time(), timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _utc_iso(value: datetime) -> str:
    return _as_utc(value).isoformat()
