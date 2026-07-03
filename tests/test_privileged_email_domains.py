from __future__ import annotations

import pytest

from app.security.identity_policy import (
    IdentityPolicyError,
    _iter_config_values,
    _valid_email_parts,
    admin_allowed_email_domains,
    canonicalize_customer_email,
    customer_email_policy_violation,
    customer_temp_email_domains,
    is_privileged_workplace_email,
    privileged_allowed_email_domains,
    require_customer_email,
    require_privileged_workplace_email,
)


def test_privileged_email_policy_accepts_only_configured_workplace_domains(app):
    with app.app_context():
        assert privileged_allowed_email_domains() == frozenset(
            {"sit.singaporetech.edu.sg", "singaporetech.edu.sg"}
        )
        assert (
            require_privileged_workplace_email("Staff.Person@SIT.SingaporeTech.edu.sg")
            == "staff.person@sit.singaporetech.edu.sg"
        )
        assert is_privileged_workplace_email("staff.person@singaporetech.edu.sg")


@pytest.mark.parametrize(
    "email",
    [
        "staff.person@gmail.com",
        "staff.person@example.com",
        "staff.person@sit.singaporetech.edu.sg.",
        "staff.person@sit.singaporetech.edu.sg\nbcc@example.com",
        "not-an-email",
    ],
)
def test_privileged_email_policy_rejects_personal_and_malformed_addresses(app, email):
    with app.app_context():
        assert not is_privileged_workplace_email(email)
        with pytest.raises(IdentityPolicyError):
            require_privileged_workplace_email(email)


def test_customer_email_policy_remains_separate_from_privileged_policy(app):
    with app.app_context():
        assert require_customer_email("customer@gmail.com") == "customer@gmail.com"
        with pytest.raises(IdentityPolicyError, match="admin_email_domain"):
            require_customer_email("customer@sit.singaporetech.edu.sg")


def test_customer_email_policy_edge_cases_fail_closed(app):
    with app.app_context():
        assert customer_email_policy_violation("not-an-email") == "invalid_email"
        with pytest.raises(IdentityPolicyError, match="invalid_email"):
            canonicalize_customer_email("+alias@gmail.com")
        assert not _valid_email_parts("customer", "@", "-invalid.example")


def test_identity_policy_config_sets_support_fallback_defaults_and_strings(app):
    with app.app_context():
        app.config.pop("ADMIN_ALLOWED_EMAIL_DOMAINS", None)
        app.config["SIT_WORKPLACE_EMAIL_DOMAINS"] = " Example.COM, second.example "
        assert admin_allowed_email_domains() == frozenset(
            {"example.com", "second.example"}
        )

        app.config.pop("CUSTOMER_TEMP_EMAIL_DOMAINS", None)
        assert "mailinator.com" in customer_temp_email_domains()
        assert _iter_config_values(None) == ()
