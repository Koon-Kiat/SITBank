from __future__ import annotations

import pytest

from app.security.identity_policy import (
    IdentityPolicyError,
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
