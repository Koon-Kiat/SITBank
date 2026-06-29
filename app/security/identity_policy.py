from __future__ import annotations

import re
from collections.abc import Iterable

from flask import current_app


EMAIL_RE = re.compile(r"^(?=\S{1,128}@\S{1,253}$)[^@\x00-\x1f\x7f]+@[^@\x00-\x1f\x7f]+$")


class IdentityPolicyError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def normalize_identity_email(email: str) -> str:
    text = str(email or "").strip()
    if "\x00" in text or "\r" in text or "\n" in text or len(text) > 255:
        raise IdentityPolicyError("invalid_email")
    local, separator, domain = text.partition("@")
    if not _valid_email_parts(local, separator, domain):
        raise IdentityPolicyError("invalid_email")
    return f"{local.casefold()}@{domain.strip().casefold()}"


def admin_allowed_email_domains() -> frozenset[str]:
    return _config_set("ADMIN_ALLOWED_EMAIL_DOMAINS", fallback_name="SIT_WORKPLACE_EMAIL_DOMAINS")


def root_admin_emails() -> frozenset[str]:
    return _config_set("ROOT_ADMIN_EMAILS")


def is_admin_workplace_email(email: str) -> bool:
    try:
        normalized = normalize_identity_email(email)
    except IdentityPolicyError:
        return False
    return _email_domain(normalized) in admin_allowed_email_domains()


def customer_email_policy_violation(email: str) -> str | None:
    try:
        normalized = normalize_identity_email(email)
    except IdentityPolicyError:
        return "invalid_email"
    if normalized in root_admin_emails():
        return "root_admin_allowlisted_email"
    if _email_domain(normalized) in admin_allowed_email_domains():
        return "admin_email_domain"
    return None


def require_customer_email(email: str) -> str:
    reason = customer_email_policy_violation(email)
    if reason:
        raise IdentityPolicyError(reason)
    return normalize_identity_email(email)


def require_admin_workplace_email(email: str) -> str:
    normalized = normalize_identity_email(email)
    if _email_domain(normalized) not in admin_allowed_email_domains():
        raise IdentityPolicyError("admin_email_domain_not_allowed")
    return normalized


def staff_personal_email_policy_violation(personal_email: str, workplace_email: str | None = None) -> str | None:
    try:
        normalized = normalize_identity_email(personal_email)
    except IdentityPolicyError:
        return "invalid_email"
    if normalized in root_admin_emails():
        return "root_admin_allowlisted_email"
    if _email_domain(normalized) in admin_allowed_email_domains():
        return "admin_email_domain"
    if workplace_email:
        try:
            normalized_workplace = normalize_identity_email(workplace_email)
        except IdentityPolicyError:
            normalized_workplace = ""
        if normalized_workplace and normalized == normalized_workplace:
            return "personal_matches_workplace"
    return None


def _config_set(name: str, *, fallback_name: str | None = None) -> frozenset[str]:
    value = current_app.config.get(name)
    if value is None and fallback_name:
        value = current_app.config.get(fallback_name)
    return frozenset(_iter_config_values(value))


def _iter_config_values(value: object) -> Iterable[str]:
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(item.strip().casefold() for item in value.split(",") if item.strip())
    return tuple(str(item).strip().casefold() for item in value if str(item).strip())


def _valid_email_parts(local: str, separator: str, domain: str) -> bool:
    domain = domain.strip()
    if separator != "@" or not local or not domain:
        return False
    if not EMAIL_RE.fullmatch(f"{local}@{domain}"):
        return False
    labels = domain.split(".")
    return all(label and not label.startswith("-") and not label.endswith("-") for label in labels)


def _email_domain(email: str) -> str:
    return email.rpartition("@")[2].casefold()
