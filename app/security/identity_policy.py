from __future__ import annotations

import re
from collections.abc import Iterable

from flask import current_app


EMAIL_RE = re.compile(r"^(?=\S{1,128}@\S{1,253}$)[^@\x00-\x1f\x7f]+@[^@\x00-\x1f\x7f]+$")
GMAIL_DOMAIN = "gmail.com"
GOOGLEMAIL_DOMAIN = "googlemail.com"
GOOGLE_CUSTOMER_EMAIL_DOMAINS = frozenset({GMAIL_DOMAIN, GOOGLEMAIL_DOMAIN})
DEFAULT_CUSTOMER_EMAIL_PLUS_ALIAS_DOMAINS = GOOGLE_CUSTOMER_EMAIL_DOMAINS
DEFAULT_CUSTOMER_EMAIL_DOT_INSENSITIVE_DOMAINS = GOOGLE_CUSTOMER_EMAIL_DOMAINS
DEFAULT_CUSTOMER_TEMP_EMAIL_DOMAINS = frozenset(
    {
        "10minutemail.com",
        "guerrillamail.com",
        "mailinator.com",
        "temp-mail.org",
        "yopmail.com",
    }
)
CUSTOMER_EMAIL_DOMAIN_ALIASES = {GOOGLEMAIL_DOMAIN: GMAIL_DOMAIN}


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


def privileged_allowed_email_domains() -> frozenset[str]:
    return admin_allowed_email_domains()


def root_admin_emails() -> frozenset[str]:
    return _config_set("ROOT_ADMIN_EMAILS")


def is_privileged_workplace_email(email: str) -> bool:
    try:
        normalized = normalize_identity_email(email)
    except IdentityPolicyError:
        return False
    return _email_domain(normalized) in privileged_allowed_email_domains()


def is_admin_workplace_email(email: str) -> bool:
    return is_privileged_workplace_email(email)


def customer_email_policy_violation(email: str) -> str | None:
    try:
        normalized = normalize_identity_email(email)
    except IdentityPolicyError:
        return "invalid_email"
    if normalized in root_admin_emails():
        return "root_admin_allowlisted_email"
    domain = _email_domain(normalized)
    if domain in admin_allowed_email_domains():
        return "admin_email_domain"
    if domain in customer_temp_email_domains():
        return "temporary_email_domain"
    return None


def require_customer_email(email: str) -> str:
    reason = customer_email_policy_violation(email)
    if reason:
        raise IdentityPolicyError(reason)
    return normalize_identity_email(email)


def canonicalize_customer_email(
    email: str,
    *,
    plus_alias_domains: Iterable[str] | None = None,
    dot_insensitive_domains: Iterable[str] | None = None,
) -> str:
    normalized = normalize_identity_email(email)
    local, _separator, domain = normalized.rpartition("@")
    plus_domains = _normalized_domain_set(
        plus_alias_domains
        if plus_alias_domains is not None
        else _config_set(
            "CUSTOMER_EMAIL_PLUS_ALIAS_DOMAINS",
            default=DEFAULT_CUSTOMER_EMAIL_PLUS_ALIAS_DOMAINS,
        )
    )
    dot_domains = _normalized_domain_set(
        dot_insensitive_domains
        if dot_insensitive_domains is not None
        else _config_set(
            "CUSTOMER_EMAIL_DOT_INSENSITIVE_DOMAINS",
            default=DEFAULT_CUSTOMER_EMAIL_DOT_INSENSITIVE_DOMAINS,
        )
    )
    if domain in plus_domains:
        local = local.partition("+")[0]
    if domain in dot_domains:
        local = local.replace(".", "")
    canonical_domain = CUSTOMER_EMAIL_DOMAIN_ALIASES.get(domain, domain)
    if not local:
        raise IdentityPolicyError("invalid_email")
    return f"{local}@{canonical_domain}"


def customer_temp_email_domains() -> frozenset[str]:
    return _config_set(
        "CUSTOMER_TEMP_EMAIL_DOMAINS",
        default=DEFAULT_CUSTOMER_TEMP_EMAIL_DOMAINS,
    )


def require_privileged_workplace_email(email: str) -> str:
    normalized = normalize_identity_email(email)
    if _email_domain(normalized) not in privileged_allowed_email_domains():
        raise IdentityPolicyError("admin_email_domain_not_allowed")
    return normalized


def require_admin_workplace_email(email: str) -> str:
    return require_privileged_workplace_email(email)


def _config_set(
    name: str,
    *,
    fallback_name: str | None = None,
    default: Iterable[str] = (),
) -> frozenset[str]:
    value = current_app.config.get(name)
    if value is None and fallback_name:
        value = current_app.config.get(fallback_name)
    if value is None:
        value = default
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


def _normalized_domain_set(values: Iterable[str]) -> frozenset[str]:
    return frozenset(str(value or "").strip().casefold() for value in values if str(value or "").strip())
