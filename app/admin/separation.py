from __future__ import annotations

from flask import has_request_context

from app.auth.services import AuthError
from app.extensions import db
from app.models import PersonIdentityLink, User
from app.security.audit import audit_event, audit_reference, audit_system_event

from .services import ACCOUNT_CUSTOMER, STAFF_ACCOUNT_TYPES


def assert_not_self_customer_action(
    actor_staff_user: User,
    target_customer_user: User,
    action_type: str,
) -> None:
    if actor_staff_user is None or target_customer_user is None:
        _block(actor_staff_user, target_customer_user, action_type, "missing_identity")
    if actor_staff_user.account_type not in STAFF_ACCOUNT_TYPES:
        _block(actor_staff_user, target_customer_user, action_type, "actor_not_staff")
    if target_customer_user.account_type != ACCOUNT_CUSTOMER:
        _block(actor_staff_user, target_customer_user, action_type, "target_not_customer")

    if _has_active_identity_link(actor_staff_user.id, target_customer_user.id):
        _block(actor_staff_user, target_customer_user, action_type, "explicit_identity_link")

    actor_emails = {
        _normalized_email(actor_staff_user.email),
        _normalized_email(actor_staff_user.staff_personal_email),
    }
    target_email = _normalized_email(target_customer_user.email)
    if target_email and target_email in actor_emails:
        _block(actor_staff_user, target_customer_user, action_type, "verified_email_overlap")


def _has_active_identity_link(staff_user_id: int, customer_user_id: int) -> bool:
    return bool(
        db.session.execute(
            db.select(PersonIdentityLink.id).where(
                PersonIdentityLink.staff_user_id == staff_user_id,
                PersonIdentityLink.customer_user_id == customer_user_id,
                PersonIdentityLink.revoked_at.is_(None),
            )
        ).scalar_one_or_none()
    )


def _block(
    actor_staff_user: User | None,
    target_customer_user: User | None,
    action_type: str,
    reason: str,
) -> None:
    metadata = {
        "action_type": str(action_type or "privileged_customer_action")[:80],
        "reason": reason,
        "target_customer_ref": audit_reference(
            "customer_user",
            getattr(target_customer_user, "id", None),
        ),
    }
    if has_request_context():
        audit_event(
            "staff_self_customer_action_blocked",
            "blocked",
            user=actor_staff_user,
            metadata=metadata,
        )
    else:
        audit_system_event(
            "staff_self_customer_action_blocked",
            "blocked",
            user_id=getattr(actor_staff_user, "id", None),
            metadata=metadata,
        )
    raise AuthError("This privileged action is not permitted for that customer account", 403)


def _normalized_email(value: str | None) -> str:
    return str(value or "").strip().casefold()
