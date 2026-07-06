from __future__ import annotations

import hmac
import ipaddress
import json
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import pyotp
from flask import current_app, request, session, url_for
from sqlalchemy import String, and_, cast, false, func, or_
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.auth.password_reset import (
    MANUAL_RECOVERY_ACTIVE_STATUSES,
    MANUAL_RECOVERY_STATUS_APPROVED,
    MANUAL_RECOVERY_STATUS_DENIED,
    MANUAL_RECOVERY_STATUS_UNDER_REVIEW,
    complete_manual_recovery_request,
    transition_manual_recovery_request,
)
from app.auth.schemas import PHONE_RE as AUTH_PHONE_RE
from app.auth.services import (
    AuthError,
    _clear_user_security_failures,
    _dummy_password_hash,
    _record_user_security_failure,
    _totp,
    _verify_totp_for_user,
)
from app.extensions import db
from app.models import (
    AdminActionRequest,
    AuthAttemptCounter,
    ManualRecoveryRequest,
    SecurityAuditEvent,
    StaffInvite,
    TransactionDispute,
    User,
)
from app.security.audit import AuditWriteError, audit_event, audit_event_required, audit_reference, principal_reference
from app.security.crypto import encrypt_mfa_secret
from app.security.email import send_security_email
from app.security.identity_policy import (
    IdentityPolicyError,
    admin_allowed_email_domains,
    is_admin_workplace_email,
    require_admin_workplace_email,
    root_admin_emails,
)
from app.security.passwords import (
    PasswordPolicyError,
    hash_password,
    is_password_raw_length_safe,
    password_hash_needs_rehash,
    validate_password_policy,
    verify_password,
)
from app.security.password_history import mark_password_changed, replace_user_password
from app.security.rate_limits import AuthBackoffRequired, apply_exponential_backoff, clear_failures, record_failure
from app.security.session_hmac import active_hmac_hex
from app.security.rate_limits import (
    DurableRateLimitExceeded,
    consume_durable_rate_limit,
    enforce_durable_failure_limit,
)
from app.security.sessions import (
    begin_password_authenticated_session,
    establish_authenticated_session,
    public_session_reference,
    revoke_all_sessions,
    revoke_current_session,
)
from app.time_display import sgt_datetime, utc_iso
from app.security.turnstile import TurnstileError, require_turnstile


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
ADMIN_ACTION_REQUEST_TTL_SECONDS = 24 * 60 * 60
ADMIN_ACTION_PENDING_STATUS = "pending"
STAFF_ACTION_OPERATION_TYPES = {
    "deactivate": "staff_deactivate",
    "reactivate": "staff_reactivate",
    "reset_activation": "staff_reset_activation",
}
MANUAL_RECOVERY_STATUS_OPERATION_TYPES = {
    MANUAL_RECOVERY_STATUS_APPROVED: "manual_recovery_approve",
    MANUAL_RECOVERY_STATUS_DENIED: "manual_recovery_deny",
}
ADMIN_ACTION_OPERATION_LABELS = {
    "staff_deactivate": "Deactivate staff account",
    "staff_reactivate": "Reactivate staff account",
    "staff_reset_activation": "Reset staff activation",
    "manual_recovery_approve": "Approve manual recovery",
    "manual_recovery_deny": "Deny manual recovery",
    "manual_recovery_complete": "Complete manual recovery",
    "customer_security_unlock": "Unlock customer security lock",
}
ADMIN_ACTION_EXECUTION_REASON = "maker_checker_approved"
ADMIN_ACTION_APPROVAL_REQUIRED_MESSAGE = "Admin action approval required"
AUTOMATIC_CUSTOMER_LOCK_REASONS = frozenset(
    {"password_failed_attempts", "mfa_failed_attempts"}
)
GENERIC_ADMIN_LOGIN_ERROR = "Invalid workplace email, password, or authentication code"
ADMIN_INDEX_ENDPOINT = "admin.index"
FRESH_MFA_REQUIRED_ERROR = "Fresh MFA verification is required"
INVITE_FRESH_MFA_REQUIRED_ERROR = (
    "Fresh MFA verification is required. Wait for a new authenticator code "
    "before retrying this invite action."
)
INVITE_CREATE_ERROR = "Invite could not be created"
INVITE_ACCEPTANCE_ERROR = "Invite acceptance failed"
INVALID_WORKPLACE_EMAIL_ERROR = "Invalid workplace email"
GENERIC_INVITE_ERROR = "Invite link is invalid or expired"
GENERIC_WORKPLACE_VERIFICATION_ERROR = "Workplace verification failed"
ADMIN_AUTH_BACKOFF_ERROR = "Too many attempts. Please try again later."
INVITE_ACCEPTANCE_SESSION_KEY = "staff_invite_acceptance_session"
STAFF_INVITE_MAX_ACCEPTANCE_STARTS = 3
STAFF_INVITE_MAX_VERIFY_ATTEMPTS = 5
STAFF_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")
FULL_NAME_RE = re.compile(r"^[^\x00-\x1f\x7f<>]{1,120}$")
PHONE_RE = re.compile(AUTH_PHONE_RE)
TOTP_RE = re.compile(r"^\d{6}$")
WORKPLACE_CODE_RE = re.compile(r"^\d{6}$")
AUDIT_EVENT_TYPE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
AUDIT_REFERENCE_RE = re.compile(r"^[A-Za-z0-9_.:@/-]{1,80}$")
AUDIT_SAFE_SEARCH_RE = re.compile(r"^[A-Za-z0-9_.:@/-]{1,80}$")
AUDIT_ALLOWED_OUTCOMES = frozenset(
    {
        "blocked",
        "expired",
        "failure",
        "locked",
        "mfa_success",
        "queued",
        "requested",
        "required",
        "success",
        "verified",
    }
)
AUDIT_SORT_OPTIONS = frozenset(
    {"timestamp", "severity", "event_type", "actor", "request_id", "source"}
)
AUDIT_EVENT_TYPE_OPTION_LIMIT = 250
AUDIT_TARGET_METADATA_KEYS = (
    "audit_event_ref",
    "invite_ref",
    "principal_ref",
    "request_ref",
    "target_customer_ref",
    "target_role",
    "target_staff_ref",
    "workplace_email_ref",
)
AUDIT_SYSTEM_SOURCE_VALUES = frozenset(
    {"privilege-check", "system", "system-probe", "scheduler", "deployment"}
)
AUDIT_SYSTEM_EVENT_PREFIXES = (
    "audit_",
    "cloudflare_",
    "database_",
    "host_",
    "mfa_dek_",
    "privilege_",
    "runtime_",
    "security_alert_",
)
AUDIT_EVENT_DESCRIPTIONS = {
    "admin_access_denied": (
        "Admin access denied",
        "A staff/admin account was blocked before admin access was granted.",
        "Confirm the account is active, workplace verified, and expected to use the admin app.",
    ),
    "admin_action_request_created": (
        "Admin approval request created",
        "A high-risk root-admin operation was queued for maker-checker approval.",
        "Review the requester, target reference, operation type, and request integrity status.",
    ),
    "admin_action_request_executed": (
        "Admin approval executed",
        "A durable privileged action request was approved and executed.",
        "Review requester, approver, target, operation type, and downstream audit events.",
    ),
    "admin_action_request_review": (
        "Admin approval queue reviewed",
        "A root admin opened the admin approval queue.",
        "Use this to correlate who reviewed pending high-risk actions.",
    ),
    "admin_dashboard_access": (
        "Admin dashboard opened",
        "A staff/admin user accessed the isolated admin dashboard.",
        "Confirm the actor role, session context, and source are expected.",
    ),
    "admin_login": (
        "Admin login blocked",
        "An admin login attempt was blocked before password verification completed.",
        "Review account status and lock reason without exposing credentials.",
    ),
    "admin_login_password": (
        "Admin password accepted",
        "An admin password check succeeded and TOTP verification was required.",
        "Correlate with a later admin MFA login event from the same actor and source.",
    ),
    "admin_logout": (
        "Admin logout",
        "An admin session logout was requested.",
        "Use this to confirm session end timing for an investigation.",
    ),
    "admin_mfa_login": (
        "Admin MFA login",
        "An admin TOTP login step was attempted or completed.",
        "Successful events establish an authenticated admin session.",
    ),
    "admin_role_authorization": (
        "Admin role authorization",
        "A route guard checked whether the actor had admin-level authority.",
        "Blocked outcomes indicate a role boundary was enforced.",
    ),
    "audit_log_detail_view": (
        "Audit detail opened",
        "An admin opened a sanitized SecurityAuditEvent detail page.",
        "This is read-only investigation activity, not a raw log query.",
    ),
    "audit_log_view": (
        "Audit log searched",
        "An admin viewed or filtered sanitized SecurityAuditEvent rows.",
        "Use filters, request ID, and actor context to reconstruct review activity.",
    ),
    "cloudflare_access_denied": (
        "Cloudflare Access denied request",
        "A Cloudflare Access assertion or boundary check rejected a request.",
        "Review source kind, route, and policy reason without copying assertions.",
    ),
    "dispute_detail_view": (
        "Dispute detail opened",
        "A plain staff account opened a transaction dispute detail page.",
        "Read-only investigation activity; correlate with later status-change events.",
    ),
    "dispute_queue_access": (
        "Dispute queue access denied",
        "An admin or root-admin session was blocked from the transaction dispute queue.",
        "This queue is deliberately staff-only; admin/root-admin oversight is via this audit log.",
    ),
    "dispute_queue_review": (
        "Dispute queue reviewed",
        "A plain staff account opened the transaction dispute queue.",
        "Use this to correlate who reviewed pending customer transaction disputes.",
    ),
    "host_deploy_wrapper": (
        "Deployment wrapper check",
        "A trusted host deployment wrapper or deployment probe reported status.",
        "Correlate with GitHub run evidence and host-side deployment logs.",
    ),
    "manual_recovery_admin_complete": (
        "Manual recovery completion requested",
        "A root admin requested completion of an approved manual recovery case.",
        "Confirm approval, maker-checker status, TOTP step-up, and target reference.",
    ),
    "manual_recovery_admin_review": (
        "Manual recovery queue reviewed",
        "A root admin accessed the manual recovery review queue.",
        "Treat unlinked requests generically; they do not prove account existence.",
    ),
    "manual_recovery_admin_transition": (
        "Manual recovery status transition",
        "A root admin attempted to move a manual recovery request through review.",
        "Confirm the requested state, reason, TOTP step-up, and maker-checker requirement.",
    ),
    "manual_recovery_completed": (
        "Manual recovery completed",
        "A manual recovery request completed and the customer MFA state was reset for re-enrollment.",
        "Confirm session revocation, notification, and follow-up customer verification.",
    ),
    "manual_recovery_notification": (
        "Manual recovery notification",
        "A manual recovery notification delivery attempt was recorded.",
        "Investigate failures through the email provider without exposing message contents.",
    ),
    "manual_recovery_requested": (
        "Manual recovery requested",
        "A public manual recovery request was received with generic account-discovery protections.",
        "Review rate-limit context and linked/unlinked state without confirming identity to users.",
    ),
    "manual_recovery_status_changed": (
        "Manual recovery status changed",
        "The manual recovery state machine accepted a status change.",
        "Use this to reconstruct the case timeline and operator reason.",
    ),
    "privilege_probe": (
        "Runtime privilege probe",
        "A runtime database or host privilege verification probe ran.",
        "Blocked or failed outcomes should stop deployment until privileges are corrected.",
    ),
    "runtime_db_privilege_verification_failed": (
        "Runtime database privilege failure",
        "A runtime database privilege verification failed.",
        "Treat this as deployment-blocking until least-privilege grants are restored.",
    ),
    "security_alert_delivery": (
        "Security alert delivery",
        "An admin requested or completed manual delivery of the current alert report.",
        "Confirm TOTP step-up, delivery outcome, and dedupe behavior.",
    ),
    "security_alert_review": (
        "Security alerts reviewed",
        "An admin opened the sanitized security alert review page.",
        "Correlate with active alert rows and audit-chain status.",
    ),
    "security_alert_scheduler": (
        "Security alert scheduler",
        "The scheduled security alert job evaluated alert conditions.",
        "Review alert count, severity, and delivery metadata.",
    ),
    "staff_account_activated": (
        "Staff account activated",
        "A staff/admin invite acceptance completed account activation.",
        "Confirm workplace verification, TOTP enrollment, and invite target reference.",
    ),
    "staff_account_lifecycle": (
        "Staff account lifecycle change",
        "A root admin requested a staff/admin account lifecycle operation.",
        "Review target role/status, TOTP step-up, and maker-checker approval.",
    ),
    "staff_account_view": (
        "Staff accounts viewed",
        "An admin viewed the staff/admin account list.",
        "Use this as read-only access evidence for staff-account investigations.",
    ),
    "staff_invite_accept": (
        "Staff invite acceptance",
        "A staff/admin invite acceptance step was attempted.",
        "Review invite state, workplace verification, and forged-field checks.",
    ),
    "staff_invite_create": (
        "Staff invite creation attempt",
        "A root admin attempted to create a staff/admin invite.",
        "Confirm role, workplace email policy, TOTP step-up, and delivery outcome.",
    ),
    "staff_invite_created": (
        "Staff invite created",
        "A staff/admin invite was created.",
        "Use the invite target reference and role; do not expose invite tokens.",
    ),
    "staff_invite_email": (
        "Staff invite email",
        "A staff/admin invite email delivery attempt was recorded.",
        "Investigate provider delivery without exposing invite tokens.",
    ),
    "staff_invite_expired": (
        "Staff invite expired",
        "A staff/admin invite expired before successful activation.",
        "Confirm no later activation occurred for the same invite reference.",
    ),
    "staff_invite_revoked": (
        "Staff invite revoked",
        "A root admin revoked an active staff/admin invite.",
        "Review the actor, target invite reference, and TOTP step-up outcome.",
    ),
    "staff_invite_reissued": (
        "Staff invite reissued",
        "A root admin rotated an active staff/admin invite token and sent a new invite email.",
        "Review delivery status without exposing invite tokens.",
    ),
    "staff_totp_setup": (
        "Staff TOTP setup",
        "A staff/admin invitee attempted or completed authenticator enrollment.",
        "Confirm setup state without exposing TOTP secret material.",
    ),
    "staff_workplace_verification": (
        "Staff workplace email verified",
        "A staff/admin invitee verified their workplace email.",
        "Correlate with invite acceptance and TOTP setup.",
    ),
    "staff_workplace_verification_sent": (
        "Staff workplace verification sent",
        "A staff/admin workplace verification code delivery attempt was recorded.",
        "Investigate provider delivery without exposing the verification code.",
    ),
    "statement_export": (
        "Monthly statement exported",
        "A customer downloaded a CSV monthly statement for a chosen period.",
        "Correlate the period reference; the exported file content itself is not logged.",
    ),
    "tailscale_admin_access": (
        "Tailscale admin access check",
        "A private admin access verification checked the Tailscale boundary.",
        "Confirm the admin host remains private and Funnel is not enabled.",
    ),
    "transaction_dispute_create": (
        "Transaction dispute filed",
        "A customer reported an issue on a transaction they were a party to.",
        "Review the transaction and issue-type reference; raw reason text is not logged here.",
    ),
    "transaction_dispute_status_change": (
        "Transaction dispute status changed",
        "A plain staff account transitioned a transaction dispute's status.",
        "Review the from/to status and dispute reference; resolution text is not logged here.",
    ),
}
AUDIT_FIELD_LEGEND = {
    "Activity": "Plain-language summary of the technical event type.",
    "Actor": "Safe actor identity: system, user ID, and privileged workplace identity when allowed.",
    "Actor role": "Role observed on the actor record or safe role metadata.",
    "Source kind": "Classifies whether the source is network, system, deployment, or another safe category.",
    "Source": "Sanitized source display such as an IP address, system probe, or deployment wrapper.",
    "Target reference": "Opaque audit reference for the affected user, invite, request, or resource.",
    "Request ID": "Correlation identifier used to connect related application events.",
    "Hash chain": "Whether this row has an audit hash and is linked into the audit chain.",
    "Hash algorithm": "Hash-chain algorithm recorded for this row.",
    "Severity": "Security severity supplied by safe metadata, when available.",
    "Outcome": "Result of the action, authorization decision, or system check.",
    "Timestamp": "Readable UTC+8/SGT time; the machine ISO timestamp remains in datetime/JSON fields.",
}
DISPLAY_REDACTED_VALUE = "[redacted]"
DISPLAY_SENSITIVE_VALUE_RE = re.compile(
    r"(?i)(bearer\s+[A-Za-z0-9._~+/=-]+|basic\s+[A-Za-z0-9._~+/=-]+|"
    r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|"
    r"(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_+/=-]{48,})"
)


def is_customer_user(user: User | None) -> bool:
    return bool(user is not None and (user.account_type or ACCOUNT_CUSTOMER) == ACCOUNT_CUSTOMER)


def is_staff_user(user: User | None) -> bool:
    return bool(user is not None and (user.account_type or ACCOUNT_CUSTOMER) in STAFF_ACCOUNT_TYPES)


def is_active_staff_user(user: User | None) -> bool:
    return bool(
        is_staff_user(user)
        and user.account_status == "active"
        and user.mfa_enabled
        and is_admin_workplace_email(str(user.email or ""))
    )


def is_root_admin(user: User | None) -> bool:
    if user is None or user.account_type != ACCOUNT_ROOT_ADMIN:
        return False
    return (
        is_admin_workplace_email(str(user.email or ""))
        and _normalize_email(user.email).casefold() in _root_admin_emails()
    )


def require_staff_session() -> User:
    user_id = session.get("user_id")
    if not user_id:
        raise AuthError("Authentication required", 401)
    user = db.session.get(User, int(user_id))
    if not is_active_staff_user(user):
        audit_event("admin_access_denied", "blocked", user=user, metadata={"reason": "not_active_staff"})
        raise AuthError("Forbidden", 403)
    return user


def is_plain_staff_user(user: User | None) -> bool:
    """True only when account_type is exactly 'staff' — excludes admin/root_admin.

    Unlike ``is_staff_user`` (staff-tier-or-above), the dispute review queue is a
    business-operations tool that admin/root_admin must not access directly; their
    oversight is limited to the generic audit log viewer.
    """
    return bool(user is not None and (user.account_type or ACCOUNT_CUSTOMER) == ACCOUNT_STAFF)


def require_plain_staff_session() -> User:
    user = require_staff_session()
    if not is_plain_staff_user(user):
        audit_event("dispute_queue_access", "blocked", user=user, metadata={"reason": "admin_or_root_admin_excluded"})
        raise AuthError("Forbidden", 403)
    return user


DISPUTE_STATUS_TRANSITIONS = {
    "open": frozenset({"under_review", "resolved", "rejected"}),
    "under_review": frozenset({"resolved", "rejected"}),
    "resolved": frozenset(),
    "rejected": frozenset(),
}


def _require_plain_staff(actor: User, event_type: str) -> None:
    if is_plain_staff_user(actor):
        return
    audit_event(event_type, "blocked", user=actor, metadata={"reason": "admin_or_root_admin_excluded"})
    raise AuthError("Forbidden", 403)


def _transaction_dispute_or_404(dispute_id: int) -> TransactionDispute:
    dispute = db.session.get(TransactionDispute, dispute_id)
    if dispute is None:
        raise AuthError("Not found", 404)
    return dispute


def public_transaction_dispute(dispute: TransactionDispute) -> dict[str, Any]:
    transaction = dispute.transaction
    reporter = dispute.reporter
    return {
        "id": dispute.id,
        "transaction_id": dispute.transaction_id,
        "transaction_ref": transaction.transaction_ref if transaction else None,
        "reporter_ref": audit_reference("customer_user", dispute.reporter_id),
        "reporter_username": reporter.username if reporter else None,
        "issue_type": dispute.issue_type,
        "reason": dispute.reason,
        "status": dispute.status,
        "resolver_ref": audit_reference("staff_user", dispute.resolver_id) if dispute.resolver_id else None,
        "resolution_note": dispute.resolution_note,
        "created_at": dispute.created_at.isoformat() if dispute.created_at else None,
        "created_at_display": _utc_display(dispute.created_at) if dispute.created_at else None,
        "decided_at": dispute.decided_at.isoformat() if dispute.decided_at else None,
        "decided_at_display": _utc_display(dispute.decided_at) if dispute.decided_at else None,
    }


def disputes_for_staff(actor: User) -> list[dict[str, Any]]:
    """List disputes for staff review.

    Read access to customer dispute content is audited with the same
    required (fail-closed) contract as dispute status changes: if the audit
    row cannot be recorded, the read does not proceed.
    """
    _require_plain_staff(actor, "dispute_queue_review")
    disputes = list(
        db.session.execute(
            db.select(TransactionDispute).order_by(
                TransactionDispute.created_at.desc(),
                TransactionDispute.id.desc(),
            )
        ).scalars()
    )
    try:
        audit_event_required("dispute_queue_review", "success", user=actor)
        db.session.commit()
    except AuditWriteError:
        db.session.rollback()
        raise
    return [public_transaction_dispute(item) for item in disputes]


def dispute_detail_for_staff(actor: User, dispute_id: int) -> dict[str, Any]:
    """Fetch one dispute's detail for staff review.

    See `disputes_for_staff` for why this read uses required (fail-closed)
    audit rather than best-effort logging.
    """
    _require_plain_staff(actor, "dispute_detail_view")
    dispute = _transaction_dispute_or_404(dispute_id)
    try:
        audit_event_required(
            "dispute_detail_view",
            "success",
            user=actor,
            metadata={"dispute_ref": audit_reference("transaction_dispute", dispute.id)},
        )
        db.session.commit()
    except AuditWriteError:
        db.session.rollback()
        raise
    return public_transaction_dispute(dispute)


def transition_dispute_status_for_staff(
    actor: User,
    dispute_id: int,
    new_status: str,
    resolution_note: str | None,
) -> dict[str, Any]:
    _require_plain_staff(actor, "transaction_dispute_status_change")
    dispute = _transaction_dispute_or_404(dispute_id)
    from_status = dispute.status
    allowed_next = DISPUTE_STATUS_TRANSITIONS.get(from_status, frozenset())
    if new_status not in allowed_next:
        audit_event(
            "transaction_dispute_status_change",
            "blocked",
            user=actor,
            metadata={
                "reason": "illegal_transition",
                "dispute_ref": audit_reference("transaction_dispute", dispute.id),
                "from_status": from_status,
                "to_status": new_status,
            },
        )
        raise AuthError("Invalid status transition", 409)

    note_text = str(resolution_note or "").strip()
    decided_at = _utcnow() if new_status in {"resolved", "rejected"} else dispute.decided_at

    # Conditional UPDATE (status must still match what we just read) makes the
    # check-then-set atomic: a concurrent transition that lands first changes
    # the row's status, so this UPDATE matches zero rows instead of racing it.
    result = db.session.execute(
        db.update(TransactionDispute)
        .where(TransactionDispute.id == dispute.id, TransactionDispute.status == from_status)
        .values(
            status=new_status,
            resolver_id=actor.id,
            resolution_note=note_text or None,
            decided_at=decided_at,
        )
    )
    if result.rowcount != 1:
        db.session.rollback()
        audit_event(
            "transaction_dispute_status_change",
            "blocked",
            user=actor,
            metadata={
                "reason": "stale_transition",
                "dispute_ref": audit_reference("transaction_dispute", dispute.id),
                "from_status": from_status,
                "to_status": new_status,
            },
        )
        raise AuthError("Dispute was already updated by another reviewer", 409)

    dispute.status = new_status
    dispute.resolver_id = actor.id
    dispute.resolution_note = note_text or None
    dispute.decided_at = decided_at
    try:
        audit_event_required(
            "transaction_dispute_status_change",
            "success",
            user=actor,
            metadata={
                "dispute_ref": audit_reference("transaction_dispute", dispute.id),
                "from_status": from_status,
                "to_status": new_status,
            },
        )
        db.session.commit()
    except AuditWriteError:
        db.session.rollback()
        raise
    return public_transaction_dispute(dispute)


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


def verify_admin_totp_step_up(actor: User, totp_code: str | None, scope: str) -> bool:
    return bool(totp_code) and _verify_totp_for_user(actor, totp_code, scope)


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
        {"label": "Dashboard", "href": url_for(ADMIN_INDEX_ENDPOINT), "endpoint": ADMIN_INDEX_ENDPOINT, "group": "overview"},
    ]
    if user.account_type == ACCOUNT_STAFF:
        items.append(
            {
                "label": "Business operations",
                "href": url_for(ADMIN_INDEX_ENDPOINT),
                "endpoint": ADMIN_INDEX_ENDPOINT,
                "group": "business",
            }
        )
        items.append(
            {
                "label": "Disputes",
                "href": url_for("admin.disputes"),
                "endpoint": "admin.disputes",
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
                {
                    "label": "Customer locks",
                    "href": url_for("admin.customer_security_locks"),
                    "endpoint": "admin.customer_security_locks",
                    "group": "root",
                },
                {
                    "label": "Approvals",
                    "href": url_for("admin.admin_action_requests"),
                    "endpoint": "admin.admin_action_requests",
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
        "business_operations": _staff_business_operations(actor),
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


def locked_customers_for_admin(actor: User) -> list[dict[str, Any]]:
    _require_active_root_admin(actor, "customer_security_unlock_review")
    customers = list(
        db.session.execute(
            db.select(User)
            .where(
                User.account_type == ACCOUNT_CUSTOMER,
                User.is_frozen.is_(True),
                User.security_locked_at.is_not(None),
                User.security_lock_reason.in_(tuple(AUTOMATIC_CUSTOMER_LOCK_REASONS)),
            )
            .order_by(User.security_locked_at.asc(), User.id.asc())
        ).scalars()
    )
    audit_event("customer_security_unlock_review", "success", user=actor)
    return [
        {
            "id": customer.id,
            "customer_ref": audit_reference("customer_user", customer.id),
            "username": customer.username,
            "lock_reason": customer.security_lock_reason,
            "locked_at": _utc_iso(customer.security_locked_at),
            "locked_at_display": _utc_display(customer.security_locked_at),
        }
        for customer in customers
    ]


def request_customer_security_unlock(
    actor: User,
    target_user_id: int,
    reason: str,
    totp_code: str | None,
) -> dict[str, Any]:
    _require_active_root_admin(actor, "customer_security_unlock_request")
    clean_reason = _require_manual_recovery_reason(
        reason,
        "customer_security_unlock_request",
        actor,
    )
    target = _locked_customer_for_update(
        target_user_id,
        actor=actor,
        event_type="customer_security_unlock_request",
    )
    _assert_not_self_customer_action(actor, target, "customer_security_unlock")
    if not totp_code or not _verify_totp_for_user(
        actor,
        totp_code,
        "customer_security_unlock_request",
    ):
        audit_event(
            "customer_security_unlock_request",
            "failure",
            user=actor,
            metadata={
                "reason": "invalid_totp_step_up",
                "target_customer_ref": audit_reference("customer_user", target.id),
            },
        )
        raise AuthError(FRESH_MFA_REQUIRED_ERROR, 403)

    request_record = _create_admin_action_request(
        actor,
        operation_type="customer_security_unlock",
        target_type="customer_user",
        target_id=str(target.id),
        operation_payload={
            "action": "unlock",
            "lock_reason": str(target.security_lock_reason),
            "locked_at": _utc_iso(target.security_locked_at),
        },
        reason=clean_reason,
    )
    audit_event(
        "customer_security_unlock_requested",
        "success",
        user=actor,
        metadata={
            "request_ref": audit_reference("admin_action_request", request_record.id),
            "target_customer_ref": audit_reference("customer_user", target.id),
            "previous_lock_reason": target.security_lock_reason,
            "actor_role": actor.account_type,
            "reason_present": True,
            "reason_length": len(clean_reason),
        },
    )
    return {
        "message": ADMIN_ACTION_APPROVAL_REQUIRED_MESSAGE,
        "request": public_admin_action_request(request_record),
    }


def transition_staff_account_as_root_admin(
    actor: User,
    target_user_id: int,
    action: str,
    totp_code: str | None,
) -> dict[str, Any]:
    normalized_action, target = _validate_staff_account_lifecycle_request(
        actor,
        target_user_id,
        action,
    )
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
        raise AuthError(FRESH_MFA_REQUIRED_ERROR, 403)

    request_record = _create_admin_action_request(
        actor,
        operation_type=STAFF_ACTION_OPERATION_TYPES[normalized_action],
        target_type="staff_user",
        target_id=str(target.id),
        operation_payload={"action": normalized_action},
        reason=None,
    )
    return {
        "message": ADMIN_ACTION_APPROVAL_REQUIRED_MESSAGE,
        "request": public_admin_action_request(request_record),
    }


def _validate_staff_account_lifecycle_request(
    actor: User,
    target_user_id: int,
    action: str,
) -> tuple[str, User]:
    if not is_root_admin(actor):
        audit_event("staff_account_lifecycle", "blocked", user=actor, metadata={"reason": "not_root_admin"})
        raise AuthError("Forbidden", 403)
    normalized_action = str(action or "").strip().casefold()
    if normalized_action not in STAFF_ACTION_OPERATION_TYPES:
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
    return normalized_action, target


def _execute_staff_account_lifecycle(
    actor: User,
    target_user_id: int,
    action: str,
) -> dict[str, Any]:
    normalized_action, target = _validate_staff_account_lifecycle_request(
        actor,
        target_user_id,
        action,
    )
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
        target.mfa_pending_started_at = None
        target.mfa_pending_session_hash = None
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
    return {"message": "Staff account updated", "account": public_staff_account(target, actor)}


def recent_audit_events_for_dashboard(actor: User, *, limit: int = 5) -> list[dict[str, Any]]:
    if role_rank(actor.account_type) < role_rank(ACCOUNT_ADMIN):
        return []
    events = list(
        db.session.execute(
            db.select(SecurityAuditEvent).order_by(SecurityAuditEvent.created_at.desc(), SecurityAuditEvent.id.desc()).limit(limit)
        ).scalars()
    )
    return [
        public_audit_event(
            event,
            include_metadata=False,
            reveal_full_ip=is_root_admin(actor),
        )
        for event in events
    ]


def query_audit_events_for_admin(actor: User, args: dict[str, Any]) -> dict[str, Any]:
    if role_rank(actor.account_type) < role_rank(ACCOUNT_ADMIN):
        audit_event("audit_log_view", "blocked", user=actor, metadata={"reason": "admin_role_required"})
        raise AuthError("Forbidden", 403)
    filters = _audit_filters(args)
    page = _bounded_int(args.get("page"), default=1, minimum=1, maximum=10000)
    per_page = _bounded_int(args.get("per_page"), default=25, minimum=1, maximum=100)
    sort = _validated_choice(args.get("sort"), AUDIT_SORT_OPTIONS, "timestamp")
    direction = _validated_choice(args.get("direction"), {"asc", "desc"}, "desc")
    statement = db.select(SecurityAuditEvent)
    statement = _apply_audit_filters(statement, filters)
    total = db.session.execute(db.select(func.count()).select_from(statement.subquery())).scalar_one()
    order_column = {
        "timestamp": SecurityAuditEvent.created_at,
        "severity": cast(SecurityAuditEvent.event_metadata, String),
        "event_type": SecurityAuditEvent.event_type,
        "actor": SecurityAuditEvent.user_id,
        "request_id": SecurityAuditEvent.correlation_id,
        "source": SecurityAuditEvent.ip_address,
    }[sort]
    if direction == "asc":
        statement = statement.order_by(order_column.asc(), SecurityAuditEvent.id.asc())
    else:
        statement = statement.order_by(order_column.desc(), SecurityAuditEvent.id.desc())
    events = list(
        db.session.execute(statement.limit(per_page).offset((page - 1) * per_page)).scalars()
    )
    total_pages = max(1, (int(total or 0) + per_page - 1) // per_page)
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
        "events": [
            public_audit_event(
                event,
                include_metadata=False,
                reveal_full_ip=is_root_admin(actor),
            )
            for event in events
        ],
        "filters": filters,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "total": int(total or 0),
        "sort": sort,
        "direction": direction,
        "sort_options": sorted(AUDIT_SORT_OPTIONS),
        "event_type_options": _audit_event_type_options(filters["event_type"]),
        "severity_options": ["low", "medium", "high", "critical"],
        "outcome_options": sorted(AUDIT_ALLOWED_OUTCOMES),
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
    return public_audit_event(
        event,
        include_metadata=True,
        reveal_full_ip=is_root_admin(actor),
    )


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
        "created_at_display": _utc_display(user.created_at),
        "last_login_at": _utc_iso(user.last_login_at) if user.last_login_at else None,
        "last_login_at_display": _utc_display(user.last_login_at) if user.last_login_at else None,
        "can_manage": bool(is_root_admin(actor) and user.account_type in ADMIN_ACCOUNT_MANAGED_TYPES and user.id != actor.id),
    }


def public_audit_event(
    event: SecurityAuditEvent,
    *,
    include_metadata: bool,
    reveal_full_ip: bool = False,
) -> dict[str, Any]:
    metadata = event.event_metadata if isinstance(event.event_metadata, dict) else {}
    source_kind, source_display = _audit_source(
        event,
        metadata,
        reveal_full_ip=reveal_full_ip,
    )
    created_at_utc = _utc_iso(event.created_at)
    activity, description, investigation_hint = _audit_event_description(event.event_type)
    payload = {
        "id": event.id,
        "event_type": event.event_type,
        "activity": activity,
        "event_description": description,
        "investigation_hint": investigation_hint,
        "outcome": event.outcome,
        "actor_user_id": event.user_id,
        "actor_role": _audit_actor_role(event, metadata),
        "actor_summary": _audit_actor_summary(event, metadata),
        "ip_address": _audit_ip_display(event.ip_address, reveal_full_ip=reveal_full_ip),
        "source_kind": source_kind,
        "source_display": source_display,
        "target_ref": _audit_target_ref(metadata),
        "request_id": event.correlation_id,
        "correlation_id": event.correlation_id,
        "session_ref": event.session_ref,
        "created_at": created_at_utc,
        "created_at_utc": created_at_utc,
        "created_at_display": _utc_display(event.created_at),
        "hash_chain_status": _audit_hash_chain_status(event),
    }
    payload["severity"] = str(metadata.get("severity") or "").strip()[:24] if metadata else ""
    if include_metadata:
        safe_metadata = _safe_metadata_for_display(metadata)
        payload["metadata"] = safe_metadata
        payload["metadata_groups"] = _audit_metadata_groups(safe_metadata)
        payload["field_legend"] = dict(AUDIT_FIELD_LEGEND)
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


def _staff_business_operations(actor: User) -> list[dict[str, str]]:
    if actor.account_type != ACCOUNT_STAFF:
        return []
    return [
        {
            "label": "Customer support queues",
            "status": "Not implemented",
            "description": "No staff customer-support or review routes are registered yet.",
        }
    ]


def _admin_security_notices(actor: User) -> list[dict[str, str]]:
    notices = [
        {
            "severity": "info",
            "title": "Authenticator MFA required",
            "message": "Staff/admin access uses workplace login plus authenticator TOTP.",
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


def _audit_event_type_options(current: str) -> list[str]:
    rows = db.session.execute(
        db.select(SecurityAuditEvent.event_type)
        .distinct()
        .order_by(SecurityAuditEvent.event_type.asc())
        .limit(AUDIT_EVENT_TYPE_OPTION_LIMIT)
    ).scalars()
    options = {
        event_type
        for event_type in rows
        if isinstance(event_type, str) and AUDIT_EVENT_TYPE_RE.fullmatch(event_type)
    }
    if current and AUDIT_EVENT_TYPE_RE.fullmatch(current):
        options.add(current)
    return sorted(options)


def _audit_actor_role(event: SecurityAuditEvent, metadata: dict[str, Any]) -> str:
    if event.user is not None and event.user.account_type:
        return str(event.user.account_type)
    for key in ("actor_role", "requester_role", "approver_role"):
        value = metadata.get(key)
        if isinstance(value, str):
            text = _safe_filter(value, 40)
            if text:
                return text
    return "system"


def _audit_actor_summary(event: SecurityAuditEvent, metadata: dict[str, Any]) -> str:
    if event.user is None:
        if event.user_id is None:
            return "system"
        return f"user:{int(event.user_id)} (unavailable)"
    role = _audit_actor_role(event, metadata)
    actor_ref = f"user:{int(event.user.id)}"
    if role in STAFF_ACCOUNT_TYPES:
        workplace_email = _safe_filter(event.user.email, 255)
        if workplace_email:
            return f"{actor_ref} ({role}, {workplace_email})"
    return f"{actor_ref} ({role})"


def _audit_event_description(event_type: str) -> tuple[str, str, str]:
    clean_event_type = _safe_filter(event_type, 80) or "unknown_event"
    configured = AUDIT_EVENT_DESCRIPTIONS.get(clean_event_type)
    if configured is not None:
        return configured
    readable = " ".join(part for part in clean_event_type.replace("-", "_").split("_") if part)
    activity = readable[:1].upper() + readable[1:] if readable else "Unknown audit event"
    return (
        activity,
        f"Recorded audit event `{clean_event_type}`.",
        "Review safe metadata, actor context, source, target reference, and request ID before escalation.",
    )


def _audit_source(
    event: SecurityAuditEvent,
    metadata: dict[str, Any],
    *,
    reveal_full_ip: bool = False,
) -> tuple[str, str]:
    configured_kind = _safe_filter(metadata.get("source_kind"), 40)
    configured_display = _safe_filter(metadata.get("source_display"), 80)
    if configured_kind and configured_display:
        return configured_kind, _audit_ip_display(
            configured_display,
            reveal_full_ip=reveal_full_ip,
        )

    source = _safe_filter(event.ip_address, 64)
    source_key = source.casefold()
    is_system_event = event.user_id is None and event.event_type.startswith(AUDIT_SYSTEM_EVENT_PREFIXES)
    if source_key in AUDIT_SYSTEM_SOURCE_VALUES or is_system_event:
        if source_key == "privilege-check" or "privilege" in event.event_type:
            return "system_probe", "Runtime privilege probe"
        return "system", "System or scheduled control"
    if event.user_id is None and source_key in {"", "unknown"}:
        return "system", "System"
    return "network", _audit_ip_display(source, reveal_full_ip=reveal_full_ip)


def _audit_ip_display(value: str | None, *, reveal_full_ip: bool) -> str:
    source = _safe_filter(value, 64)
    if reveal_full_ip or not source:
        return source or "unknown"
    try:
        address = ipaddress.ip_address(source)
    except ValueError:
        return source
    prefix = 24 if address.version == 4 else 64
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def _audit_target_ref(metadata: dict[str, Any]) -> str:
    for key in AUDIT_TARGET_METADATA_KEYS:
        value = metadata.get(key)
        if isinstance(value, str):
            text = _safe_filter(value, 120)
            if text:
                return text
    return ""


def _audit_hash_chain_status(event: SecurityAuditEvent) -> dict[str, Any]:
    return {
        "algorithm": _safe_filter(event.hash_algorithm, 32),
        "event_hash_present": bool(event.event_hash),
        "previous_hash_present": bool(event.previous_event_hash),
        "linked": bool(event.event_hash),
    }


def _audit_metadata_groups(metadata: dict[str, Any]) -> dict[str, dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {
        "Actor and session": {},
        "Request and source": {},
        "Target": {},
        "Security decision": {},
        "Result and system": {},
        "Other safe metadata": {},
    }
    for key, value in metadata.items():
        lowered = key.casefold()
        if any(term in lowered for term in ("actor", "principal", "session", "requester", "approver")):
            groups["Actor and session"][key] = value
        elif any(term in lowered for term in ("source", "ip", "route", "method", "validator", "jwks")):
            groups["Request and source"][key] = value
        elif key in AUDIT_TARGET_METADATA_KEYS or "target" in lowered or lowered.endswith("_ref"):
            groups["Target"][key] = value
        elif any(term in lowered for term in ("reason", "severity", "policy", "required", "decision")):
            groups["Security decision"][key] = value
        elif any(term in lowered for term in ("count", "status", "result", "revoked", "probe", "anchor", "chain")):
            groups["Result and system"][key] = value
        else:
            groups["Other safe metadata"][key] = value
    return {name: values for name, values in groups.items() if values}


def _audit_filters(args: dict[str, Any]) -> dict[str, str]:
    return {
        "event_type": _safe_identifier_filter(args.get("event_type"), AUDIT_EVENT_TYPE_RE),
        "actor": _safe_actor_filter(args.get("actor")),
        "target": _safe_identifier_filter(args.get("target"), AUDIT_REFERENCE_RE),
        "role": _validated_choice(args.get("role"), STAFF_ACCOUNT_TYPES | {ACCOUNT_CUSTOMER}, ""),
        "severity": _validated_choice(args.get("severity"), {"low", "medium", "high", "critical"}, ""),
        "outcome": _validated_choice(args.get("outcome") or args.get("status"), AUDIT_ALLOWED_OUTCOMES, ""),
        "ip_address": _safe_identifier_filter(args.get("ip_address"), AUDIT_REFERENCE_RE),
        "request_id": _safe_identifier_filter(args.get("request_id") or args.get("correlation_id"), AUDIT_REFERENCE_RE),
        "from": _safe_filter(args.get("from"), 40),
        "to": _safe_filter(args.get("to"), 40),
        "q": _safe_identifier_filter(args.get("q"), AUDIT_SAFE_SEARCH_RE),
    }


def _apply_audit_filters(statement, filters: dict[str, str]):
    if filters["event_type"]:
        statement = statement.where(SecurityAuditEvent.event_type == filters["event_type"])
    if filters["outcome"]:
        statement = statement.where(SecurityAuditEvent.outcome == filters["outcome"])
    statement = _apply_audit_actor_filter(statement, filters["actor"])
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
    if filters["severity"]:
        statement = _where_metadata_key_matches(statement, "severity", filters["severity"], exact=True)
    if filters["target"]:
        statement = _where_any_metadata_key_matches(statement, AUDIT_TARGET_METADATA_KEYS, filters["target"])
    statement = _apply_audit_search_filter(statement, filters["q"])
    return statement


def _apply_audit_actor_filter(statement, actor: str):
    if not actor:
        return statement
    try:
        actor_id = int(actor)
    except ValueError:
        return statement
    return statement.where(SecurityAuditEvent.user_id == actor_id)


def _apply_audit_search_filter(statement, query: str):
    if not query:
        return statement
    pattern = f"%{_like_escape(query)}%"
    matching_event_types = tuple(
        event_type
        for event_type, description in AUDIT_EVENT_DESCRIPTIONS.items()
        if query.casefold() in " ".join(description).casefold()
    )
    search_fields = [
        SecurityAuditEvent.event_type.ilike(pattern, escape="\\"),
        SecurityAuditEvent.outcome.ilike(pattern, escape="\\"),
        SecurityAuditEvent.correlation_id.ilike(pattern, escape="\\"),
        SecurityAuditEvent.ip_address.ilike(pattern, escape="\\"),
        SecurityAuditEvent.event_metadata["source_kind"].as_string().ilike(pattern, escape="\\"),
        SecurityAuditEvent.event_metadata["source_display"].as_string().ilike(pattern, escape="\\"),
        SecurityAuditEvent.user.has(
            or_(
                User.username.ilike(pattern, escape="\\"),
                _privileged_workplace_email_matches(pattern),
            )
        ),
    ]
    search_fields.extend(
        SecurityAuditEvent.event_metadata[key].as_string().ilike(pattern, escape="\\")
        for key in AUDIT_TARGET_METADATA_KEYS
    )
    if matching_event_types:
        search_fields.append(SecurityAuditEvent.event_type.in_(matching_event_types))
    if query.isdigit():
        search_fields.append(SecurityAuditEvent.user_id == int(query))
    return statement.where(or_(*search_fields))


def _privileged_workplace_email_matches(pattern: str):
    domain_matches = [
        func.lower(User.email).like(
            f"%@{_like_escape(domain)}",
            escape="\\",
        )
        for domain in admin_allowed_email_domains()
    ]
    allowed_domain = or_(*domain_matches) if domain_matches else false()
    return and_(
        User.account_type.in_(tuple(STAFF_ACCOUNT_TYPES)),
        allowed_domain,
        User.email.ilike(pattern, escape="\\"),
    )


def _where_metadata_key_matches(statement, key: str, value: str, *, exact: bool):
    metadata_value = SecurityAuditEvent.event_metadata[key].as_string()
    if exact:
        return statement.where(metadata_value == value)
    return statement.where(metadata_value.ilike(f"%{_like_escape(value)}%", escape="\\"))


def _where_any_metadata_key_matches(statement, keys: tuple[str, ...], value: str):
    pattern = f"%{_like_escape(value)}%"
    return statement.where(
        or_(
            *(SecurityAuditEvent.event_metadata[key].as_string().ilike(pattern, escape="\\") for key in keys)
        )
    )


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
            allowed[key_text] = [_safe_display_value(key_text, item, 120) for item in list(value)[:10]]
            continue
        if isinstance(value, dict):
            allowed[key_text] = {
                _safe_filter(nested_key, 64): _safe_display_value(nested_key, nested_value, 120)
                for nested_key, nested_value in list(value.items())[:10]
                if _safe_filter(nested_key, 64)
                and not _display_key_is_sensitive(_safe_filter(nested_key, 64))
            }
            continue
        allowed[key_text] = _safe_display_value(key_text, value, 160)
    return allowed


def _safe_display_value(key: Any, value: Any, limit: int) -> str:
    text = _safe_filter(value, limit)
    if not text:
        return ""
    if _display_value_is_sensitive(str(key), text):
        return DISPLAY_REDACTED_VALUE
    return text


def _display_value_is_sensitive(key: str, text: str) -> bool:
    if _display_key_is_sensitive(key):
        return True
    return bool(DISPLAY_SENSITIVE_VALUE_RE.search(text))


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


def _safe_identifier_filter(value: Any, pattern: re.Pattern[str]) -> str:
    text = _safe_filter(value, 80)
    return text if pattern.fullmatch(text) else ""


def _safe_actor_filter(value: Any) -> str:
    text = _safe_filter(value, 32)
    return text if text.isdigit() else ""


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


def _normalize_admin_login_email(workplace_email: str, password: str) -> str:
    try:
        return normalize_workplace_email(workplace_email)
    except AuthError as exc:
        normalized_email = _normalize_email(workplace_email)
        principal = _auth_principal(normalized_email)
        _enforce_auth_backoff("admin_login", principal)
        if is_password_raw_length_safe(password):
            verify_password(password, _dummy_password_hash())
        audit_event(
            "admin_login",
            "failure",
            metadata={
                "known_user": False,
                "reason": "invalid_workplace_email",
                "principal_ref": principal_reference(normalized_email),
            },
        )
        record_failure("admin_login", principal)
        raise AuthError(GENERIC_ADMIN_LOGIN_ERROR, 401) from exc


def _admin_password_matches(user: User | None, password: str) -> bool:
    if not is_password_raw_length_safe(password):
        return False
    candidate_hash = user.password_hash if user else _dummy_password_hash()
    return verify_password(password, candidate_hash)


def authenticate_admin_primary(workplace_email: str, password: str) -> dict[str, Any]:
    normalized_email = _normalize_admin_login_email(workplace_email, password)
    principal = _auth_principal(normalized_email)
    _enforce_auth_backoff("admin_login", principal)

    user = _staff_user_by_workplace_email(normalized_email)
    password_ok = _admin_password_matches(user, password)

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
                "reason": "invalid_credentials_or_ineligible_staff",
                "principal_ref": principal_reference(normalized_email),
            },
        )
        record_failure("admin_login", principal)
        if user is not None and not password_ok:
            user.failed_login_count = int(user.failed_login_count or 0) + 1
            _record_user_security_failure(
                user,
                "password",
                "password_failed_attempts",
            )
        raise AuthError(GENERIC_ADMIN_LOGIN_ERROR, 401)

    if user.is_frozen or user.security_locked_at is not None:
        audit_event("admin_login", "blocked", user=user, metadata={"reason": user.security_lock_reason or "locked"})
        raise AuthError(GENERIC_ADMIN_LOGIN_ERROR, 401)

    if password_hash_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    db.session.commit()
    clear_failures(
        "admin_mfa_login",
        _admin_mfa_failure_principal(user.id),
    )
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
    principal = _admin_mfa_failure_principal(user.id)
    failure_limit = int(current_app.config["ADMIN_MFA_FAILURE_LIMIT"])
    failure_window_seconds = int(
        current_app.config["ADMIN_MFA_FAILURE_WINDOW_SECONDS"]
    )
    try:
        enforce_durable_failure_limit(
            "admin_mfa_login",
            principal,
            limit=failure_limit,
        )
    except DurableRateLimitExceeded as exc:
        audit_event(
            "admin_mfa_login",
            "blocked",
            user=user,
            metadata={
                "reason": "wrong_code_threshold_exceeded",
                "retry_after": exc.retry_after,
            },
        )
        raise AuthError(
            GENERIC_ADMIN_LOGIN_ERROR,
            429,
            retry_after=exc.retry_after,
        ) from exc
    if not _verify_totp_for_user(
        user,
        totp_code,
        "admin_mfa_login",
        track_failures=False,
    ):
        attempts = record_failure(
            "admin_mfa_login",
            principal,
            window_seconds=failure_window_seconds,
        )
        outcome = "blocked" if attempts > failure_limit else "failure"
        audit_event(
            "admin_mfa_login",
            outcome,
            user=user,
            metadata={
                "reason": (
                    "wrong_code_threshold_exceeded"
                    if attempts > failure_limit
                    else "invalid_totp"
                ),
                "failure_count": attempts,
            },
        )
        if attempts > failure_limit:
            try:
                enforce_durable_failure_limit(
                    "admin_mfa_login",
                    principal,
                    limit=failure_limit,
                )
            except DurableRateLimitExceeded as exc:
                raise AuthError(
                    GENERIC_ADMIN_LOGIN_ERROR,
                    429,
                    retry_after=exc.retry_after,
                ) from exc
        raise AuthError(GENERIC_ADMIN_LOGIN_ERROR, 401)
    clear_failures("admin_mfa_login", principal)
    user.failed_login_count = 0
    user.last_login_at = _utcnow()
    db.session.commit()
    clear_failures("admin_login", _auth_principal(user.email))
    _clear_user_security_failures(user, "password")
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
    workplace_email: str,
    role: str,
    totp_code: str | None,
) -> dict[str, Any]:
    if not is_root_admin(actor):
        audit_event("staff_invite_create", "blocked", user=actor, metadata={"reason": "not_root_admin"})
        raise AuthError("Forbidden", 403)

    try:
        normalized_workplace = normalize_workplace_email(workplace_email)
    except AuthError:
        audit_event("staff_invite_create", "blocked", user=actor, metadata={"reason": "email_policy"})
        raise
    normalized_role = str(role or "").strip().casefold()
    if normalized_role not in INVITABLE_ROLES:
        audit_event("staff_invite_create", "failure", user=actor, metadata={"reason": "invalid_role"})
        raise AuthError("Invalid invite role", 400)
    if normalized_role == ACCOUNT_ROOT_ADMIN:
        raise AuthError("Invalid invite role", 400)
    _require_staff_invite_step_up(
        actor,
        totp_code,
        scope="staff_invite_create",
        event_type="staff_invite_create",
    )
    _reject_root_admin_allowlist_invite_target(normalized_workplace, actor, "staff_invite_create")
    _reject_existing_staff_identity(normalized_workplace)
    _reject_active_invite(normalized_workplace)

    token = secrets.token_urlsafe(32)
    now = _utcnow()
    invite = StaffInvite(
        token_hash=invite_token_hash(token),
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
        raise AuthError(INVITE_CREATE_ERROR, 400) from exc

    invite_url = url_for("admin.invite_accept_info", token=token, _external=True)
    try:
        _send_invite_email(invite, invite_url)
    except Exception as exc:
        current_app.logger.warning("staff_invite_email_failed error=%s", type(exc).__name__)
        invite.status = "revoked"
        invite.revoked_at = _utcnow()
        invite.revoked_by_user_id = actor.id
        audit_event(
            "staff_invite_email",
            "failure",
            user=actor,
            metadata={**_invite_audit_metadata(invite), "reason": "email_delivery_failed"},
        )
        db.session.commit()
        raise AuthError("Invite could not be sent", 503) from exc
    audit_event("staff_invite_email", "queued", user=actor, metadata=_invite_audit_metadata(invite))
    db.session.commit()
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
    _require_staff_invite_step_up(
        actor,
        totp_code,
        scope="staff_invite_revoke",
        event_type="staff_invite_revoked",
    )
    invite = db.session.get(StaffInvite, int(invite_id))
    if invite is None or invite.status not in ACTIVE_INVITE_STATUSES:
        raise AuthError("Invite not found", 404)
    invite.status = "revoked"
    invite.revoked_at = _utcnow()
    invite.revoked_by_user_id = actor.id
    audit_event_required("staff_invite_revoked", "success", user=actor, metadata=_invite_audit_metadata(invite))
    db.session.commit()
    return {"message": "Invite revoked", "invite": public_invite(invite)}


def reissue_staff_invite(actor: User, invite_id: int, totp_code: str | None) -> dict[str, Any]:
    if not is_root_admin(actor):
        raise AuthError("Forbidden", 403)
    _require_staff_invite_step_up(
        actor,
        totp_code,
        scope="staff_invite_reissue",
        event_type="staff_invite_reissued",
    )
    invite = db.session.get(StaffInvite, int(invite_id))
    if invite is None or invite.status not in ACTIVE_INVITE_STATUSES:
        raise AuthError("Invite not found", 404)

    _reset_active_invite_acceptance_for_root_action(
        invite,
        actor,
        event_type="staff_invite_reissued",
    )
    token = secrets.token_urlsafe(32)
    now = _utcnow()
    invite.token_hash = invite_token_hash(token)
    invite.status = "pending"
    invite.expires_at = now + timedelta(seconds=int(current_app.config["STAFF_INVITE_TTL_SECONDS"]))
    invite.last_attempt_at = now
    invite.revoked_at = None
    invite.revoked_by_user_id = None
    db.session.flush()

    invite_url = url_for("admin.invite_accept_info", token=token, _external=True)
    try:
        _send_invite_email(invite, invite_url)
    except Exception as exc:
        current_app.logger.warning("staff_invite_email_failed error=%s", type(exc).__name__)
        metadata = _invite_audit_metadata(invite)
        db.session.rollback()
        audit_event(
            "staff_invite_email",
            "failure",
            user=actor,
            metadata={**metadata, "reason": "email_delivery_failed"},
        )
        db.session.commit()
        raise AuthError("Invite could not be sent", 503) from exc

    audit_event_required(
        "staff_invite_reissued",
        "success",
        user=actor,
        metadata=_invite_audit_metadata(invite),
    )
    audit_event("staff_invite_email", "queued", user=actor, metadata=_invite_audit_metadata(invite))
    db.session.commit()
    return {"message": "Invite reissued", "invite": public_invite(invite)}


def reset_staff_invite_acceptance(actor: User, invite_id: int, totp_code: str | None) -> dict[str, Any]:
    if not is_root_admin(actor):
        raise AuthError("Forbidden", 403)
    _require_staff_invite_step_up(
        actor,
        totp_code,
        scope="staff_invite_accept_reset",
        event_type="staff_invite_accept_reset",
    )
    invite = db.session.get(StaffInvite, int(invite_id))
    if invite is None or invite.status not in ACTIVE_INVITE_STATUSES:
        raise AuthError("Invite not found", 404)

    _reset_active_invite_acceptance_for_root_action(
        invite,
        actor,
        event_type="staff_invite_accept_reset",
    )
    invite.status = "pending"
    invite.last_attempt_at = _utcnow()
    audit_event_required(
        "staff_invite_accept_reset",
        "success",
        user=actor,
        metadata=_invite_audit_metadata(invite),
    )
    db.session.commit()
    return {"message": "Invite acceptance reset", "invite": public_invite(invite)}


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
        raise AuthError(FRESH_MFA_REQUIRED_ERROR, 403)

    _assert_not_self_manual_recovery_action(actor, request_id, "manual_recovery_transition")
    if normalized_status in MANUAL_RECOVERY_STATUS_OPERATION_TYPES:
        _validate_manual_recovery_transition_request(actor, request_id, normalized_status)
        request_record = _create_admin_action_request(
            actor,
            operation_type=MANUAL_RECOVERY_STATUS_OPERATION_TYPES[normalized_status],
            target_type="manual_recovery_request",
            target_id=str(int(request_id)),
            operation_payload={"status": normalized_status},
            reason=clean_reason,
        )
        return {
            "message": ADMIN_ACTION_APPROVAL_REQUIRED_MESSAGE,
            "request": public_admin_action_request(request_record),
        }

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
        raise AuthError(FRESH_MFA_REQUIRED_ERROR, 403)

    _assert_not_self_manual_recovery_action(actor, request_id, "manual_recovery_complete")
    _validate_manual_recovery_completion_request(actor, request_id)
    request_record = _create_admin_action_request(
        actor,
        operation_type="manual_recovery_complete",
        target_type="manual_recovery_request",
        target_id=str(int(request_id)),
        operation_payload={"action": "complete"},
        reason=clean_reason,
    )
    return {
        "message": ADMIN_ACTION_APPROVAL_REQUIRED_MESSAGE,
        "request": public_admin_action_request(request_record),
    }


def admin_action_requests_for_admin(actor: User) -> list[dict[str, Any]]:
    _require_active_root_admin(actor, "admin_action_request_review")
    _expire_stale_admin_action_requests(actor)
    requests = list(
        db.session.execute(
            db.select(AdminActionRequest).order_by(
                AdminActionRequest.created_at.desc(),
                AdminActionRequest.id.desc(),
            )
        ).scalars()
    )
    audit_event("admin_action_request_review", "success", user=actor)
    return [public_admin_action_request(item) for item in requests]


def admin_action_request_detail_for_admin(actor: User, request_id: int) -> dict[str, Any]:
    _require_active_root_admin(actor, "admin_action_request_detail")
    request_record = _admin_action_request_or_error(request_id)
    _expire_admin_action_request_if_stale(request_record, actor)
    audit_event(
        "admin_action_request_detail",
        "success",
        user=actor,
        metadata={"request_ref": audit_reference("admin_action_request", request_record.id)},
    )
    return public_admin_action_request(request_record)


def approve_admin_action_request_as_root_admin(
    actor: User,
    request_id: int,
    totp_code: str | None,
) -> dict[str, Any]:
    _require_active_root_admin(actor, "admin_action_request_approve")
    request_record = _pending_admin_action_request_or_error(request_id, actor)
    _assert_admin_action_request_hmac_valid(request_record, actor)
    _assert_requester_still_eligible(request_record, actor)
    if request_record.requester_id == actor.id:
        audit_event(
            "admin_action_request_approve",
            "blocked",
            user=actor,
            metadata={
                "reason": "self_approval_denied",
                "request_ref": audit_reference("admin_action_request", request_record.id),
            },
        )
        raise AuthError("Requester cannot approve their own admin action request", 403)
    if not totp_code or not _verify_totp_for_user(actor, totp_code, f"admin_action_approve_{request_record.operation_type}"):
        audit_event(
            "admin_action_request_approve",
            "failure",
            user=actor,
            metadata={
                "reason": "invalid_totp_step_up",
                "request_ref": audit_reference("admin_action_request", request_record.id),
            },
        )
        raise AuthError(FRESH_MFA_REQUIRED_ERROR, 403)

    try:
        result = _execute_admin_action_request(actor, request_record)
    except (SQLAlchemyError, RuntimeError, TypeError, ValueError) as exc:
        db.session.rollback()
        failed_request = _admin_action_request_or_error(request_id)
        _mark_admin_action_request_execution_failed(
            actor,
            failed_request,
            reason="execution_error",
            error_type=type(exc).__name__,
        )
        raise AuthError("Admin action request execution failed", 409) from exc

    notification_user_id = result.pop("_notification_user_id", None)
    request_record.approver_id = actor.id
    request_record.status = "executed"
    request_record.decided_at = _utcnow()
    request_record.executed_at = request_record.decided_at
    audit_event_required(
        "admin_action_request_executed",
        "success",
        user=actor,
        metadata={
            "request_ref": audit_reference("admin_action_request", request_record.id),
            "operation_type": request_record.operation_type,
            "target_type": request_record.target_type,
            "target_ref": _admin_action_target_ref(request_record),
            "requester_ref": audit_reference("admin_user", request_record.requester_id),
        },
    )
    db.session.commit()
    if notification_user_id is not None:
        _send_customer_security_unlock_notification(int(notification_user_id))
    return {
        "message": "Admin action request approved and executed",
        "request": public_admin_action_request(request_record),
        "result": result,
    }


def reject_admin_action_request_as_root_admin(
    actor: User,
    request_id: int,
    totp_code: str | None,
) -> dict[str, Any]:
    _require_active_root_admin(actor, "admin_action_request_reject")
    request_record = _pending_admin_action_request_or_error(request_id, actor)
    _assert_admin_action_request_hmac_valid(request_record, actor)
    if request_record.requester_id == actor.id:
        audit_event(
            "admin_action_request_reject",
            "blocked",
            user=actor,
            metadata={
                "reason": "self_rejection_denied",
                "request_ref": audit_reference("admin_action_request", request_record.id),
            },
        )
        raise AuthError("Requester cannot reject their own admin action request", 403)
    if not totp_code or not _verify_totp_for_user(actor, totp_code, f"admin_action_reject_{request_record.operation_type}"):
        audit_event(
            "admin_action_request_reject",
            "failure",
            user=actor,
            metadata={
                "reason": "invalid_totp_step_up",
                "request_ref": audit_reference("admin_action_request", request_record.id),
            },
        )
        raise AuthError(FRESH_MFA_REQUIRED_ERROR, 403)
    request_record.approver_id = actor.id
    request_record.status = "rejected"
    request_record.decided_at = _utcnow()
    audit_event(
        "admin_action_request_rejected",
        "success",
        user=actor,
        metadata={
            "request_ref": audit_reference("admin_action_request", request_record.id),
            "operation_type": request_record.operation_type,
        },
    )
    db.session.commit()
    if request_record.operation_type == "customer_security_unlock":
        audit_event(
            "customer_security_unlock_denied",
            "blocked",
            user=actor,
            metadata={
                "request_ref": audit_reference("admin_action_request", request_record.id),
                "target_customer_ref": _admin_action_target_ref(request_record),
                "actor_role": actor.account_type,
            },
        )
    return {"message": "Admin action request rejected", "request": public_admin_action_request(request_record)}


def cancel_admin_action_request_as_root_admin(
    actor: User,
    request_id: int,
    totp_code: str | None,
) -> dict[str, Any]:
    _require_active_root_admin(actor, "admin_action_request_cancel")
    request_record = _pending_admin_action_request_or_error(request_id, actor)
    _assert_admin_action_request_hmac_valid(request_record, actor)
    if request_record.requester_id != actor.id:
        audit_event(
            "admin_action_request_cancel",
            "blocked",
            user=actor,
            metadata={
                "reason": "not_requester",
                "request_ref": audit_reference("admin_action_request", request_record.id),
            },
        )
        raise AuthError("Only the requester can cancel this admin action request", 403)
    if not totp_code or not _verify_totp_for_user(actor, totp_code, f"admin_action_cancel_{request_record.operation_type}"):
        audit_event(
            "admin_action_request_cancel",
            "failure",
            user=actor,
            metadata={
                "reason": "invalid_totp_step_up",
                "request_ref": audit_reference("admin_action_request", request_record.id),
            },
        )
        raise AuthError(FRESH_MFA_REQUIRED_ERROR, 403)
    request_record.status = "cancelled"
    request_record.decided_at = _utcnow()
    audit_event(
        "admin_action_request_cancelled",
        "success",
        user=actor,
        metadata={
            "request_ref": audit_reference("admin_action_request", request_record.id),
            "operation_type": request_record.operation_type,
        },
    )
    db.session.commit()
    return {"message": "Admin action request cancelled", "request": public_admin_action_request(request_record)}


def public_admin_action_request(request_record: AdminActionRequest) -> dict[str, Any]:
    payload = dict(request_record.operation_payload or {})
    return {
        "id": request_record.id,
        "operation_type": request_record.operation_type,
        "operation_label": _admin_action_operation_label(request_record.operation_type),
        "target_type": request_record.target_type,
        "target_ref": _admin_action_target_ref(request_record),
        "target_summary": _admin_action_target_summary(request_record),
        "payload": _safe_admin_action_payload(payload),
        "requester_ref": audit_reference("admin_user", request_record.requester_id),
        "requester_summary": _admin_action_user_summary(request_record.requester, request_record.requester_id),
        "requester_role": request_record.requester_role,
        "approver_ref": audit_reference("admin_user", request_record.approver_id)
        if request_record.approver_id
        else None,
        "approver_summary": _admin_action_user_summary(request_record.approver, request_record.approver_id)
        if request_record.approver_id
        else None,
        "status": request_record.status,
        "reason_present": bool(request_record.reason_present),
        "reason_length": int(request_record.reason_length or 0),
        "created_at": request_record.created_at.isoformat() if request_record.created_at else None,
        "created_at_display": _utc_display(request_record.created_at) if request_record.created_at else None,
        "expires_at": request_record.expires_at.isoformat() if request_record.expires_at else None,
        "expires_at_display": _utc_display(request_record.expires_at) if request_record.expires_at else None,
        "decided_at": request_record.decided_at.isoformat() if request_record.decided_at else None,
        "decided_at_display": _utc_display(request_record.decided_at) if request_record.decided_at else None,
        "executed_at": request_record.executed_at.isoformat() if request_record.executed_at else None,
        "executed_at_display": _utc_display(request_record.executed_at) if request_record.executed_at else None,
    }


def _admin_action_operation_label(operation_type: str) -> str:
    operation = str(operation_type or "").strip()
    return ADMIN_ACTION_OPERATION_LABELS.get(operation, operation.replace("_", " ").capitalize())


def _admin_action_user_summary(user: User | None, user_id: int | None) -> str:
    if user is None:
        return audit_reference("admin_user", user_id) if user_id else "Unknown admin user"
    label = user.username or user.full_name or f"User {user.id}"
    email = user.email if user.email else "no workplace email"
    return f"{label} ({role_label(user.account_type)}, {email})"


def _admin_action_target_summary(request_record: AdminActionRequest) -> str:
    target_type = str(request_record.target_type or "")
    target_id = str(request_record.target_id or "")
    if target_id.isdigit():
        summary = _admin_action_known_target_summary(target_type, int(target_id))
        if summary:
            return summary
    return _admin_action_target_ref(request_record) or "Unknown target"


def _admin_action_known_target_summary(target_type: str, target_id: int) -> str | None:
    if target_type == "staff_user":
        return _admin_action_user_target_summary(target_id, include_role=True)
    if target_type == "customer_user":
        return _admin_action_user_target_summary(target_id, include_role=False)
    if target_type == "manual_recovery_request":
        return _admin_action_manual_recovery_target_summary(target_id)
    return None


def _admin_action_user_target_summary(target_id: int, *, include_role: bool) -> str | None:
    target = db.session.get(User, target_id)
    if target is None:
        return None
    label = target.username or target.full_name or f"User {target.id}"
    if include_role:
        return f"{label} ({role_label(target.account_type)}, {target.email})"
    return f"{label} (customer)"


def _admin_action_manual_recovery_target_summary(target_id: int) -> str | None:
    request_record_target = db.session.get(ManualRecoveryRequest, target_id)
    if request_record_target is None:
        return None
    customer = db.session.get(User, request_record_target.user_id) if request_record_target.user_id else None
    customer_label = f" for {customer.username}" if customer else ""
    return f"Manual recovery request #{request_record_target.id}{customer_label} ({request_record_target.status})"


def _create_admin_action_request(
    actor: User,
    *,
    operation_type: str,
    target_type: str,
    target_id: str,
    operation_payload: dict[str, Any],
    reason: str | None,
) -> AdminActionRequest:
    _require_active_root_admin(actor, "admin_action_request_create")
    now = _utcnow()
    reason_text = str(reason or "").strip()
    request_record = AdminActionRequest(
        operation_type=operation_type,
        target_type=target_type,
        target_id=str(target_id),
        operation_payload=_safe_admin_action_payload(operation_payload),
        requester_id=actor.id,
        requester_role=actor.account_type,
        status=ADMIN_ACTION_PENDING_STATUS,
        reason_present=bool(reason_text),
        reason_length=len(reason_text),
        metadata_hmac="pending",
        created_at=now,
        updated_at=now,
        expires_at=now + timedelta(seconds=ADMIN_ACTION_REQUEST_TTL_SECONDS),
    )
    db.session.add(request_record)
    db.session.flush()
    request_record.metadata_hmac = _admin_action_request_hmac(request_record)
    audit_event_required(
        "admin_action_request_created",
        "success",
        user=actor,
        metadata={
            "request_ref": audit_reference("admin_action_request", request_record.id),
            "operation_type": operation_type,
            "target_type": target_type,
            "target_ref": _admin_action_target_ref(request_record),
            "reason_present": bool(reason_text),
            "reason_length": len(reason_text),
        },
    )
    db.session.commit()
    return request_record


def _execute_admin_action_request(actor: User, request_record: AdminActionRequest) -> dict[str, Any]:
    if request_record.operation_type in STAFF_ACTION_OPERATION_TYPES.values():
        return _execute_staff_admin_action_request(actor, request_record)
    if request_record.operation_type in {"manual_recovery_approve", "manual_recovery_deny"}:
        return _execute_manual_recovery_transition_admin_action_request(actor, request_record)
    if request_record.operation_type == "manual_recovery_complete":
        return _execute_manual_recovery_complete_admin_action_request(actor, request_record)
    if request_record.operation_type == "customer_security_unlock":
        return _execute_customer_security_unlock_admin_action_request(actor, request_record)
    raise AuthError("Admin action request cannot be executed", 409)


def _execute_staff_admin_action_request(
    actor: User,
    request_record: AdminActionRequest,
) -> dict[str, Any]:
    action = str((request_record.operation_payload or {}).get("action") or "")
    return _execute_staff_account_lifecycle(actor, int(request_record.target_id), action)


def _execute_manual_recovery_transition_admin_action_request(
    actor: User,
    request_record: AdminActionRequest,
) -> dict[str, Any]:
    status = str((request_record.operation_payload or {}).get("status") or "")
    _assert_not_self_manual_recovery_action(actor, int(request_record.target_id), "manual_recovery_transition")
    result = transition_manual_recovery_request(
        int(request_record.target_id),
        status,
        reason=ADMIN_ACTION_EXECUTION_REASON,
    )
    audit_event(
        "manual_recovery_admin_transition",
        "success",
        user=actor,
        metadata={
            "request_ref": audit_reference("manual_recovery_request", request_record.target_id),
            "new_status": result["status"],
            "reason_recorded": True,
            "maker_checker_request_ref": audit_reference("admin_action_request", request_record.id),
        },
    )
    return {"message": "Manual recovery request updated", "request": result}


def _execute_manual_recovery_complete_admin_action_request(
    actor: User,
    request_record: AdminActionRequest,
) -> dict[str, Any]:
    _assert_not_self_manual_recovery_action(actor, int(request_record.target_id), "manual_recovery_complete")
    result = complete_manual_recovery_request(
        int(request_record.target_id),
        reason=ADMIN_ACTION_EXECUTION_REASON,
    )
    audit_event(
        "manual_recovery_admin_complete",
        "success",
        user=actor,
        metadata={
            "request_ref": audit_reference("manual_recovery_request", request_record.target_id),
            "maker_checker_request_ref": audit_reference("admin_action_request", request_record.id),
            "mfa_reenrollment_required": bool(result.get("mfa_reenrollment_required")),
            "revoked_sessions": int(result.get("revoked_sessions") or 0),
        },
    )
    return {"message": "Manual recovery request completed", "request": result}


def _execute_customer_security_unlock_admin_action_request(
    actor: User,
    request_record: AdminActionRequest,
) -> dict[str, Any]:
    target = _locked_customer_for_update(
        int(request_record.target_id),
        actor=actor,
        event_type="customer_security_unlock_execute",
    )
    _assert_not_self_customer_action(actor, target, "customer_security_unlock")
    expected_reason = str(
        (request_record.operation_payload or {}).get("lock_reason") or ""
    )
    expected_locked_at = str(
        (request_record.operation_payload or {}).get("locked_at") or ""
    )
    current_reason = str(target.security_lock_reason or "").casefold()
    current_locked_at = _utc_iso(target.security_locked_at).casefold()
    if not (
        hmac.compare_digest(current_reason, expected_reason)
        and hmac.compare_digest(current_locked_at, expected_locked_at)
    ):
        audit_event(
            "customer_security_unlock_execute",
            "blocked",
            user=actor,
            metadata={
                "reason": "stale_lock_state",
                "request_ref": audit_reference("admin_action_request", request_record.id),
                "target_customer_ref": audit_reference("customer_user", target.id),
            },
        )
        raise AuthError("Customer security lock state changed", 409)

    previous_lock_reason = str(target.security_lock_reason)
    relevant_counters = list(
        db.session.execute(
            db.select(AuthAttemptCounter).where(
                AuthAttemptCounter.user_id == target.id,
                AuthAttemptCounter.scope.in_(
                    ("user_security:password", "user_security:mfa")
                ),
            )
        ).scalars()
    )
    for counter in relevant_counters:
        db.session.delete(counter)

    target.is_frozen = False
    target.security_locked_at = None
    target.security_lock_reason = None
    target.failed_login_count = 0
    revoked_sessions = revoke_all_sessions(
        target.id,
        ended_reason="security_unlock",
        component="customer",
    )
    audit_event_required(
        "customer_security_unlock_completed",
        "success",
        user=actor,
        metadata={
            "request_ref": audit_reference("admin_action_request", request_record.id),
            "target_customer_ref": audit_reference("customer_user", target.id),
            "previous_lock_reason": previous_lock_reason,
            "actor_role": actor.account_type,
            "revoked_sessions": revoked_sessions,
            "cleared_user_security_counters": len(relevant_counters),
        },
    )
    return {
        "message": "Customer security lock cleared",
        "customer_ref": audit_reference("customer_user", target.id),
        "revoked_sessions": revoked_sessions,
        "_notification_user_id": target.id,
    }


def _mark_admin_action_request_execution_failed(
    actor: User,
    request_record: AdminActionRequest,
    *,
    reason: str,
    error_type: str,
) -> None:
    request_record.approver_id = actor.id
    request_record.status = "execution_failed"
    request_record.decided_at = request_record.decided_at or _utcnow()
    audit_event_required(
        "admin_action_request_execute",
        "failure",
        user=actor,
        metadata={
            "reason": reason,
            "error_type": str(error_type or "")[:80],
            "request_ref": audit_reference("admin_action_request", request_record.id),
            "operation_type": request_record.operation_type,
        },
    )
    db.session.commit()


def _pending_admin_action_request_or_error(request_id: int, actor: User) -> AdminActionRequest:
    request_record = _admin_action_request_or_error(request_id)
    _expire_admin_action_request_if_stale(request_record, actor)
    if request_record.status != ADMIN_ACTION_PENDING_STATUS:
        audit_event(
            "admin_action_request_state",
            "blocked",
            user=actor,
            metadata={
                "reason": "not_pending",
                "request_ref": audit_reference("admin_action_request", request_record.id),
                "status": request_record.status,
            },
        )
        raise AuthError("Admin action request is not pending", 409)
    return request_record


def _admin_action_request_or_error(request_id: int) -> AdminActionRequest:
    request_record = db.session.get(AdminActionRequest, int(request_id))
    if request_record is None:
        raise AuthError("Admin action request not found", 404)
    return request_record


def _expire_stale_admin_action_requests(actor: User) -> None:
    now = _utcnow()
    stale = list(
        db.session.execute(
            db.select(AdminActionRequest).where(
                AdminActionRequest.status == ADMIN_ACTION_PENDING_STATUS,
                AdminActionRequest.expires_at <= now,
            )
        ).scalars()
    )
    for request_record in stale:
        request_record.status = "expired"
        request_record.decided_at = now
        audit_event(
            "admin_action_request_expired",
            "success",
            user=actor,
            metadata={
                "request_ref": audit_reference("admin_action_request", request_record.id),
                "operation_type": request_record.operation_type,
            },
        )
    if stale:
        db.session.commit()


def _expire_admin_action_request_if_stale(request_record: AdminActionRequest, actor: User) -> None:
    if request_record.status != ADMIN_ACTION_PENDING_STATUS:
        return
    if _as_utc(request_record.expires_at) > _utcnow():
        return
    request_record.status = "expired"
    request_record.decided_at = _utcnow()
    audit_event(
        "admin_action_request_expired",
        "success",
        user=actor,
        metadata={
            "request_ref": audit_reference("admin_action_request", request_record.id),
            "operation_type": request_record.operation_type,
        },
    )
    db.session.commit()
    raise AuthError("Admin action request is expired", 409)


def _assert_requester_still_eligible(request_record: AdminActionRequest, actor: User) -> None:
    requester = db.session.get(User, int(request_record.requester_id))
    if not _is_active_root_admin(requester):
        audit_event(
            "admin_action_request_approve",
            "blocked",
            user=actor,
            metadata={
                "reason": "requester_ineligible",
                "request_ref": audit_reference("admin_action_request", request_record.id),
            },
        )
        raise AuthError("Admin action requester is no longer eligible", 409)


def _assert_admin_action_request_hmac_valid(request_record: AdminActionRequest, actor: User) -> None:
    expected = _admin_action_request_hmac(request_record)
    if not hmac.compare_digest(str(request_record.metadata_hmac or ""), expected):
        audit_event(
            "admin_action_request_integrity",
            "failure",
            user=actor,
            metadata={"request_ref": audit_reference("admin_action_request", request_record.id)},
        )
        raise AuthError("Admin action request integrity check failed", 409)


def _admin_action_request_hmac(request_record: AdminActionRequest) -> str:
    payload = {
        "id": int(request_record.id),
        "operation_type": request_record.operation_type,
        "target_type": request_record.target_type,
        "target_id": request_record.target_id,
        "operation_payload": _safe_admin_action_payload(request_record.operation_payload or {}),
        "requester_id": int(request_record.requester_id),
        "requester_role": request_record.requester_role,
        "reason_present": bool(request_record.reason_present),
        "reason_length": int(request_record.reason_length or 0),
        "created_at": _datetime_hmac_value(request_record.created_at),
        "expires_at": _datetime_hmac_value(request_record.expires_at),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return active_hmac_hex(f"admin-action-request:{canonical}", length=64)


def _safe_admin_action_payload(payload: dict[str, Any]) -> dict[str, str]:
    safe: dict[str, str] = {}
    for key, value in dict(payload or {}).items():
        key_text = str(key or "").strip()
        if key_text not in {"action", "status", "lock_reason", "locked_at"}:
            continue
        value_text = str(value or "").strip().casefold()
        if value_text:
            safe[key_text] = value_text
    return safe


def _admin_action_target_ref(request_record: AdminActionRequest) -> str | None:
    return audit_reference(request_record.target_type, request_record.target_id)


def _datetime_hmac_value(value: datetime | None) -> str:
    if value is None:
        return ""
    return _as_utc(value).isoformat()


def _is_active_root_admin(user: User | None) -> bool:
    return bool(is_root_admin(user) and is_active_staff_user(user))


def _require_active_root_admin(actor: User, event_type: str) -> None:
    if _is_active_root_admin(actor):
        return
    audit_event(event_type, "blocked", user=actor, metadata={"reason": "not_active_root_admin"})
    raise AuthError("Forbidden", 403)


def _locked_customer_for_update(
    target_user_id: int,
    *,
    actor: User,
    event_type: str,
) -> User:
    target = db.session.execute(
        db.select(User)
        .where(User.id == int(target_user_id))
        .with_for_update()
    ).scalar_one_or_none()
    valid = bool(
        target is not None
        and target.account_type == ACCOUNT_CUSTOMER
        and target.is_frozen
        and target.security_locked_at is not None
        and target.security_lock_reason in AUTOMATIC_CUSTOMER_LOCK_REASONS
    )
    if valid:
        return target
    audit_event(
        event_type,
        "blocked",
        user=actor,
        metadata={
            "reason": "target_not_eligible",
            "target_customer_ref": audit_reference(
                "customer_user",
                target_user_id,
            ),
        },
    )
    raise AuthError("Customer security lock is not eligible for unlock", 409)


def _assert_not_self_customer_action(
    actor: User,
    target: User,
    action_type: str,
) -> None:
    from app.admin.separation import assert_not_self_customer_action

    assert_not_self_customer_action(actor, target, action_type)


def _send_customer_security_unlock_notification(user_id: int) -> None:
    user = db.session.get(User, int(user_id))
    if user is None or user.account_type != ACCOUNT_CUSTOMER:
        audit_event(
            "customer_security_unlock_notification",
            "failure",
            metadata={
                "reason": "customer_unavailable",
                "target_customer_ref": audit_reference("customer_user", user_id),
            },
        )
        return
    body = (
        "Your SITBank account security lock was cleared after an approved "
        "support review. Existing sessions were revoked. You may retry normal "
        "login or password reset; authenticator MFA and all rate limits still apply. "
        "If you did not request help, contact support immediately."
    )
    try:
        send_security_email(
            user.email,
            "SITBank account security lock cleared",
            body,
        )
    except Exception as exc:
        current_app.logger.warning(
            "customer_security_unlock_notification_failed error=%s",
            type(exc).__name__,
        )
        audit_event(
            "customer_security_unlock_notification",
            "failure",
            user=user,
            metadata={"reason": "email_delivery_failed"},
        )
        return
    audit_event(
        "customer_security_unlock_notification",
        "queued",
        user=user,
    )


def invite_info(token: str) -> dict[str, Any]:
    _consume_invite_probe_limit(token)
    invite = _active_invite_by_token(token, audit_failures=True)
    _ensure_invite_identity_policy(invite, "staff_invite_info")
    if _invite_acceptance_is_locked(invite):
        audit_event(
            "staff_invite_info",
            "blocked",
            metadata={**_invite_audit_metadata(invite), "reason": "acceptance_locked"},
        )
        raise AuthError(GENERIC_INVITE_ERROR, 401)
    return {"message": "Invite can be accepted"}


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
    _consume_invite_probe_limit(token)
    _reject_forged_invite_fields(request_fields)
    try:
        require_turnstile("admin_invite_accept", turnstile_token)
    except TurnstileError as exc:
        audit_event("staff_invite_accept", "failure", metadata={"reason": "turnstile_failed"})
        raise AuthError(INVITE_ACCEPTANCE_ERROR, 400) from exc

    invite = _active_invite_by_token(token, lock=True, audit_failures=True)
    _ensure_invite_identity_policy(invite, "staff_invite_accept")
    session_hash = _invite_acceptance_session_hash(invite.id, create=True)
    _ensure_invite_acceptance_can_start(invite, session_hash)
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
            staff_personal_email=None,
            mfa_enabled=False,
        )
        mark_password_changed(user)
        db.session.add(user)
        db.session.flush()
        invite.setup_user_id = user.id
    else:
        if invite.acceptance_session_hash:
            _ensure_invite_acceptance_session(invite, session_hash)
        if user.account_status != "setup_pending" or user.account_type != invite.role:
            raise AuthError(GENERIC_INVITE_ERROR, 401)
        user.full_name = name
        user.phone_number = phone
        replace_user_password(user, password)
        user.staff_personal_email = None

    secret = pyotp.random_base32(length=32)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(secret, user.id)
    user.mfa_enabled = False
    user.mfa_pending_started_at = _utcnow()
    user.mfa_pending_session_hash = _staff_invite_mfa_binding(invite.id)
    invite.status = "totp_pending"
    invite.last_attempt_at = _utcnow()
    invite.acceptance_session_hash = session_hash
    invite.acceptance_started_at = _utcnow()
    invite.acceptance_start_count = int(invite.acceptance_start_count or 0) + 1
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
        raise AuthError(INVITE_ACCEPTANCE_ERROR, 503) from exc
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
    _consume_invite_probe_limit(token)
    _reject_forged_invite_fields(request_fields)
    invite = _active_invite_by_token(token, lock=True, audit_failures=True)
    _ensure_invite_identity_policy(invite, "staff_invite_accept")
    if _invite_acceptance_is_locked(invite):
        audit_event(
            "staff_invite_accept",
            "blocked",
            metadata={**_invite_audit_metadata(invite), "reason": "acceptance_locked"},
        )
        raise AuthError(INVITE_ACCEPTANCE_ERROR, 429)
    _ensure_invite_acceptance_session(
        invite,
        _invite_acceptance_session_hash(invite.id, create=False),
    )
    user = db.session.get(User, invite.setup_user_id) if invite.setup_user_id else None
    if user is None or user.account_status != "setup_pending" or user.account_type != invite.role:
        audit_event("staff_invite_accept", "failure", metadata={"reason": "setup_missing"})
        raise AuthError(GENERIC_INVITE_ERROR, 401)
    if not _staff_invite_mfa_setup_is_active(user, invite.id):
        user.mfa_secret_nonce = None
        user.mfa_secret_ciphertext = None
        user.mfa_pending_started_at = None
        user.mfa_pending_session_hash = None
        invite.status = "pending"
        db.session.commit()
        audit_event("staff_totp_setup", "expired", user=user)
        raise AuthError(GENERIC_INVITE_ERROR, 401)
    if not TOTP_RE.fullmatch(str(totp_code or "")):
        _record_invite_acceptance_verify_failure(invite, user, "invalid_totp_format")
        raise AuthError("Invalid authentication code.", 401)
    if not _verify_totp_for_user(user, totp_code, "staff_totp_setup"):
        _record_invite_acceptance_verify_failure(invite, user, "invalid_totp")
        raise AuthError("Invalid authentication code.", 401)
    if not _verify_workplace_code(invite, workplace_verification_code):
        _record_invite_acceptance_verify_failure(invite, user, "invalid_workplace_code")
        raise AuthError(GENERIC_WORKPLACE_VERIFICATION_ERROR, 401)

    now = _utcnow()
    _clear_invite_acceptance_state(invite)
    user.mfa_enabled = True
    user.mfa_pending_started_at = None
    user.mfa_pending_session_hash = None
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


def _staff_invite_mfa_binding(invite_id: int) -> str:
    return active_hmac_hex(f"staff-invite-mfa:{int(invite_id)}", length=64)


def _invite_acceptance_is_locked(invite: StaffInvite) -> bool:
    return bool(invite.acceptance_locked_at or invite.acceptance_verify_locked_at)


def _invite_acceptance_session_hash(invite_id: int, *, create: bool) -> str:
    raw_value = session.get(INVITE_ACCEPTANCE_SESSION_KEY)
    if not isinstance(raw_value, str) or len(raw_value) < 32:
        if not create:
            return ""
        raw_value = secrets.token_urlsafe(32)
        session[INVITE_ACCEPTANCE_SESSION_KEY] = raw_value
        session.permanent = True
        session.modified = True
    return active_hmac_hex(
        f"staff-invite-acceptance-session:{int(invite_id)}:{raw_value}",
        length=64,
    )


def _ensure_invite_acceptance_can_start(invite: StaffInvite, session_hash: str) -> None:
    if _invite_acceptance_is_locked(invite):
        audit_event(
            "staff_invite_accept",
            "blocked",
            metadata={**_invite_audit_metadata(invite), "reason": "acceptance_locked"},
        )
        raise AuthError(INVITE_ACCEPTANCE_ERROR, 429)
    if invite.acceptance_session_hash:
        _ensure_invite_acceptance_session(invite, session_hash)
    if int(invite.acceptance_start_count or 0) >= STAFF_INVITE_MAX_ACCEPTANCE_STARTS:
        invite.acceptance_locked_at = _utcnow()
        audit_event(
            "staff_invite_accept",
            "blocked",
            metadata={**_invite_audit_metadata(invite), "reason": "restart_limit"},
        )
        db.session.commit()
        raise AuthError(INVITE_ACCEPTANCE_ERROR, 429)


def _ensure_invite_acceptance_session(invite: StaffInvite, session_hash: str) -> None:
    if not invite.acceptance_session_hash:
        audit_event(
            "staff_invite_accept",
            "blocked",
            metadata={**_invite_audit_metadata(invite), "reason": "session_binding_missing"},
        )
        raise AuthError(GENERIC_INVITE_ERROR, 401)
    if not session_hash or not hmac.compare_digest(str(invite.acceptance_session_hash), str(session_hash)):
        audit_event(
            "staff_invite_accept",
            "blocked",
            metadata={**_invite_audit_metadata(invite), "reason": "session_mismatch"},
        )
        raise AuthError(GENERIC_INVITE_ERROR, 401)


def _record_invite_acceptance_verify_failure(invite: StaffInvite, user: User, reason: str) -> None:
    invite.acceptance_verify_count = int(invite.acceptance_verify_count or 0) + 1
    metadata = {
        **_invite_audit_metadata(invite),
        "reason": reason,
        "failure_count": invite.acceptance_verify_count,
    }
    if invite.acceptance_verify_count >= STAFF_INVITE_MAX_VERIFY_ATTEMPTS:
        invite.acceptance_verify_locked_at = _utcnow()
        audit_event("staff_invite_accept_verify", "locked", user=user, metadata=metadata)
        db.session.commit()
        raise AuthError(GENERIC_INVITE_ERROR, 429)
    event_type = "staff_workplace_verification" if reason == "invalid_workplace_code" else "staff_totp_setup"
    audit_event(event_type, "failure", user=user, metadata=metadata)
    db.session.commit()


def _clear_invite_acceptance_state(invite: StaffInvite) -> None:
    invite.acceptance_session_hash = None
    invite.acceptance_started_at = None
    invite.acceptance_start_count = 0
    invite.acceptance_locked_at = None
    invite.acceptance_verify_count = 0
    invite.acceptance_verify_locked_at = None
    invite.workplace_verification_code_hmac = None
    invite.workplace_verification_sent_at = None
    invite.workplace_verification_expires_at = None
    invite.workplace_verified_at = None
    session.pop(INVITE_ACCEPTANCE_SESSION_KEY, None)


def _consume_invite_probe_limit(token: str) -> None:
    try:
        consume_durable_rate_limit(
            "staff_invite_probe",
            f"{request.remote_addr or 'unknown'}:{str(token or '')}",
            limit=10,
            window_seconds=15 * 60,
        )
    except DurableRateLimitExceeded as exc:
        audit_event(
            "staff_invite_accept",
            "blocked",
            metadata={"reason": "durable_rate_limit"},
        )
        raise AuthError(
            "Too many attempts. Please try again later.",
            429,
            retry_after=exc.retry_after,
        ) from exc


def _staff_invite_mfa_setup_is_active(user: User, invite_id: int) -> bool:
    started_at = user.mfa_pending_started_at
    if started_at is None:
        return False
    age = (_utcnow() - _as_utc(started_at)).total_seconds()
    expected_binding = _staff_invite_mfa_binding(invite_id)
    return (
        0 <= age <= int(current_app.config["PENDING_MFA_MAX_AGE_SECONDS"])
        and hmac.compare_digest(
            str(user.mfa_pending_session_hash or ""),
            expected_binding,
        )
    )


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
        "workplace_email": invite.workplace_email_normalized,
        "role": invite.role,
        "status": invite.status,
        "created_at": _utc_iso(invite.created_at),
        "created_at_display": _utc_display(invite.created_at),
        "expires_at": _utc_iso(invite.expires_at),
        "expires_at_display": _utc_display(invite.expires_at),
        "used_at": _utc_iso(invite.used_at) if invite.used_at else None,
        "used_at_display": _utc_display(invite.used_at) if invite.used_at else None,
        "revoked_at": _utc_iso(invite.revoked_at) if invite.revoked_at else None,
        "revoked_at_display": _utc_display(invite.revoked_at) if invite.revoked_at else None,
        "acceptance_start_count": int(invite.acceptance_start_count or 0),
        "acceptance_verify_count": int(invite.acceptance_verify_count or 0),
        "acceptance_locked": _invite_acceptance_is_locked(invite),
        "acceptance_locked_at": _utc_iso(
            invite.acceptance_locked_at or invite.acceptance_verify_locked_at
        )
        if _invite_acceptance_is_locked(invite)
        else None,
        "acceptance_locked_at_display": _utc_display(
            invite.acceptance_locked_at or invite.acceptance_verify_locked_at
        )
        if _invite_acceptance_is_locked(invite)
        else None,
    }


def public_manual_recovery_request(request_record: ManualRecoveryRequest) -> dict[str, Any]:
    return {
        "id": request_record.id,
        "status": request_record.status,
        "active": request_record.status in MANUAL_RECOVERY_ACTIVE_STATUSES,
        "request_count": int(request_record.request_count or 0),
        "created_at": _utc_iso(request_record.created_at),
        "created_at_display": _utc_display(request_record.created_at),
        "updated_at": _utc_iso(request_record.updated_at),
        "updated_at_display": _utc_display(request_record.updated_at),
        "expires_at": _utc_iso(request_record.expires_at),
        "expires_at_display": _utc_display(request_record.expires_at),
        "completed": request_record.completed_at is not None,
        "completed_at": _utc_iso(request_record.completed_at) if request_record.completed_at else None,
        "completed_at_display": _utc_display(request_record.completed_at) if request_record.completed_at else None,
        "linked_customer": request_record.user_id is not None,
    }


def normalize_workplace_email(email: str) -> str:
    try:
        normalized = require_admin_workplace_email(email)
    except IdentityPolicyError as exc:
        raise AuthError(INVALID_WORKPLACE_EMAIL_ERROR, 400) from exc
    local = normalized.partition("@")[0]
    if _contains_alias_separator(local):
        raise AuthError(INVALID_WORKPLACE_EMAIL_ERROR, 400)
    return normalized


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
        _audit_invalid_invite_attempt("malformed_token", enabled=audit_failures)
        raise
    statement = db.select(StaffInvite).where(StaffInvite.token_hash == token_hash)
    if lock and db.engine.dialect.name == "postgresql":
        statement = statement.with_for_update()
    invite = db.session.execute(statement).scalar_one_or_none()
    now = _utcnow()
    if invite is None:
        _audit_invalid_invite_attempt("missing", enabled=audit_failures)
        raise AuthError(GENERIC_INVITE_ERROR, 401)
    invite.last_attempt_at = now
    if _as_utc(invite.expires_at) <= now:
        invite.status = "expired"
        db.session.commit()
        audit_event("staff_invite_expired", "expired", metadata=_invite_audit_metadata(invite))
        raise AuthError(GENERIC_INVITE_ERROR, 401)
    if invite.revoked_at is not None or invite.status == "revoked":
        _audit_invalid_invite_attempt("revoked", enabled=audit_failures)
        raise AuthError(GENERIC_INVITE_ERROR, 401)
    if invite.used_at is not None or invite.status == "accepted":
        _audit_invalid_invite_attempt("used", enabled=audit_failures)
        raise AuthError(GENERIC_INVITE_ERROR, 401)
    if invite.status not in ACTIVE_INVITE_STATUSES:
        raise AuthError(GENERIC_INVITE_ERROR, 401)
    return invite


def _audit_invalid_invite_attempt(reason: str, *, enabled: bool) -> None:
    if enabled:
        audit_event(
            "staff_invite_invalid_attempt",
            "failure",
            metadata={"reason": reason},
        )


def _ensure_invite_identity_policy(invite: StaffInvite, event_type: str) -> None:
    try:
        normalize_workplace_email(invite.workplace_email_normalized)
    except AuthError:
        audit_event(event_type, "blocked", metadata={**_invite_audit_metadata(invite), "reason": "email_policy"})
        raise AuthError(GENERIC_INVITE_ERROR, 401)


def _require_staff_invite_step_up(
    actor: User,
    totp_code: str | None,
    *,
    scope: str,
    event_type: str,
) -> None:
    if not totp_code:
        audit_event(event_type, "failure", user=actor, metadata={"reason": "missing_totp_step_up"})
        raise AuthError(INVITE_FRESH_MFA_REQUIRED_ERROR, 403)
    try:
        valid = _verify_totp_for_user(actor, totp_code, scope)
    except AuthError as exc:
        audit_event(
            event_type,
            "blocked",
            user=actor,
            metadata={"reason": "totp_backoff", "retry_after": exc.retry_after},
        )
        raise AuthError(
            INVITE_FRESH_MFA_REQUIRED_ERROR,
            exc.status_code,
            retry_after=exc.retry_after,
        ) from exc
    if not valid:
        audit_event(event_type, "failure", user=actor, metadata={"reason": "invalid_totp_step_up"})
        raise AuthError(INVITE_FRESH_MFA_REQUIRED_ERROR, 403)


def _reset_active_invite_acceptance_for_root_action(
    invite: StaffInvite,
    actor: User,
    *,
    event_type: str,
) -> None:
    setup_user = db.session.get(User, invite.setup_user_id) if invite.setup_user_id else None
    if setup_user is not None:
        if (
            setup_user.account_status != "setup_pending"
            or setup_user.email.casefold() != invite.workplace_email_normalized.casefold()
        ):
            audit_event(
                event_type,
                "blocked",
                user=actor,
                metadata={**_invite_audit_metadata(invite), "reason": "setup_user_not_resettable"},
            )
            raise AuthError(GENERIC_INVITE_ERROR, 409)
        invite.setup_user_id = None
        db.session.flush()
        db.session.delete(setup_user)
    _clear_invite_acceptance_state(invite)


def _send_invite_email(invite: StaffInvite, invite_url: str) -> None:
    send_security_email(
        invite.workplace_email_normalized,
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


def _assert_not_self_manual_recovery_action(actor: User, request_id: int, action_type: str) -> None:
    from app.admin.separation import assert_not_self_customer_action

    request_record = db.session.get(ManualRecoveryRequest, int(request_id))
    if request_record is None or request_record.user_id is None:
        return
    target_customer = db.session.get(User, request_record.user_id)
    if target_customer is None:
        return
    assert_not_self_customer_action(actor, target_customer, action_type)


def _validate_manual_recovery_transition_request(actor: User, request_id: int, status: str) -> None:
    request_record = db.session.get(ManualRecoveryRequest, int(request_id))
    if request_record is None:
        audit_event(
            "manual_recovery_admin_transition",
            "blocked",
            user=actor,
            metadata={"reason": "request_not_found"},
        )
        raise AuthError("Manual recovery request not found", 404)
    if _as_utc(request_record.expires_at) <= _utcnow():
        request_record.status = "expired"
        request_record.status_changed_at = _utcnow()
        audit_event(
            "manual_recovery_admin_transition",
            "blocked",
            user=actor,
            metadata={
                "reason": "request_expired",
                "request_ref": audit_reference("manual_recovery_request", request_id),
            },
        )
        db.session.commit()
        raise AuthError("Manual recovery request is expired", 409)
    allowed = {
        "pending": frozenset({MANUAL_RECOVERY_STATUS_DENIED}),
        MANUAL_RECOVERY_STATUS_UNDER_REVIEW: frozenset(
            {MANUAL_RECOVERY_STATUS_APPROVED, MANUAL_RECOVERY_STATUS_DENIED}
        ),
    }
    if status not in allowed.get(str(request_record.status or ""), frozenset()):
        audit_event(
            "manual_recovery_admin_transition",
            "failure",
            user=actor,
            metadata={
                "reason": "invalid_transition",
                "request_ref": audit_reference("manual_recovery_request", request_id),
            },
        )
        raise AuthError("Invalid manual recovery status transition", 409)


def _validate_manual_recovery_completion_request(actor: User, request_id: int) -> None:
    request_record = db.session.get(ManualRecoveryRequest, int(request_id))
    if request_record is None:
        audit_event(
            "manual_recovery_admin_complete",
            "blocked",
            user=actor,
            metadata={"reason": "request_not_found"},
        )
        raise AuthError("Manual recovery request not found", 404)
    if _as_utc(request_record.expires_at) <= _utcnow():
        request_record.status = "expired"
        request_record.status_changed_at = _utcnow()
        audit_event(
            "manual_recovery_admin_complete",
            "blocked",
            user=actor,
            metadata={
                "reason": "request_expired",
                "request_ref": audit_reference("manual_recovery_request", request_id),
            },
        )
        db.session.commit()
        raise AuthError("Manual recovery request is expired", 409)
    if request_record.status != MANUAL_RECOVERY_STATUS_APPROVED:
        audit_event(
            "manual_recovery_admin_complete",
            "failure",
            user=actor,
            metadata={
                "reason": "completion_requires_approval",
                "request_ref": audit_reference("manual_recovery_request", request_id),
            },
        )
        raise AuthError("Manual recovery request must be approved before completion", 409)


def _reject_existing_staff_identity(workplace_email: str) -> None:
    existing = db.session.execute(
        db.select(User).where(
            func.lower(User.email) == workplace_email.casefold(),
            User.account_type.in_(tuple(STAFF_ACCOUNT_TYPES)),
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise AuthError(INVITE_CREATE_ERROR, 400)


def _reject_root_admin_allowlist_invite_target(workplace_email: str, actor: User, event_type: str) -> None:
    if workplace_email.casefold() not in _root_admin_emails():
        return
    audit_event(
        event_type,
        "blocked",
        user=actor,
        metadata={
            "reason": "root_admin_allowlist_target",
            "workplace_email_ref": audit_reference("staff_workplace_email", workplace_email),
        },
    )
    raise AuthError(INVITE_CREATE_ERROR, 400)


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
        raise AuthError(INVITE_ACCEPTANCE_ERROR, 400)


def _reject_active_invite(workplace_email: str) -> None:
    now = _utcnow()
    existing = db.session.execute(
        db.select(StaffInvite).where(
            StaffInvite.status.in_(tuple(ACTIVE_INVITE_STATUSES)),
            StaffInvite.revoked_at.is_(None),
            StaffInvite.used_at.is_(None),
            StaffInvite.expires_at > now,
            func.lower(StaffInvite.workplace_email_normalized) == workplace_email.casefold(),
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise AuthError(INVITE_CREATE_ERROR, 400)


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
    provisioning_uri = _totp(secret).provisioning_uri(
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
        "target_role": invite.role,
        "status": invite.status,
    }


def _auth_principal(identifier: str) -> str:
    return f"{request.remote_addr or 'unknown'}:{_normalize_email(identifier).casefold()}"


def _admin_mfa_failure_principal(user_id: int) -> str:
    source = str(request.remote_addr or "unknown").strip().casefold()
    return f"{source}:staff-user:{int(user_id)}"


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


def _contains_alias_separator(local: str) -> bool:
    separators = tuple(current_app.config.get("STAFF_INVITE_ALIAS_SEPARATORS") or ("+",))
    return any(separator and separator in local for separator in separators)


def _workplace_domains() -> frozenset[str]:
    return admin_allowed_email_domains()


def _root_admin_emails() -> frozenset[str]:
    return root_admin_emails()


def _utcnow() -> datetime:
    return datetime.fromtimestamp(time.time(), timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _utc_iso(value: datetime) -> str:
    return utc_iso(value)


def _utc_display(value: datetime) -> str:
    return sgt_datetime(value)
