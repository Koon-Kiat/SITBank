import re
from pathlib import Path


def test_public_repository_and_readme_index_wording_is_current():
    sonarqube = Path("docs/security/assurance/sonarqube.md").read_text(
        encoding="utf-8"
    )
    readme = Path("README.md").read_text(encoding="utf-8")

    assert "Mode And Private-Repository Decision" not in sonarqube
    assert "private `Koon-Kiat/SITBank`" not in sonarqube
    assert "`Koon-Kiat/SITBank` is public" in sonarqube
    assert "[SonarQube Cloud](" in readme
    assert "[Secret scanning](" in readme
    assert "Archived EC2 transition notes" not in readme


def test_turnstile_docs_match_deployment_wiring_without_secret_values():
    docs = "\n".join(
        Path(path).read_text(encoding="utf-8")
        for path in ("docs/DEPLOYMENT.md", "docs/OPERATIONS.md")
    )

    assert "TURNSTILE_*_ENABLED" in docs
    assert "PROD_TURNSTILE_SECRET_KEY" in docs
    assert "STAGING_TURNSTILE_SECRET_KEY" in docs
    assert "TURNSTILE_SECRET_KEY_FILE=/run/secrets/turnstile_secret_key" in docs
    assert "admin app remains private behind Tailscale" in docs
    assert "TURNSTILE_CUSTOMER_MANUAL_RECOVERY_ENABLED" in docs
    assert "TURNSTILE_FAIL_CLOSED_IN_PRODUCTION" in docs
    assert "Keep both\nadmin route flags false" not in docs


def test_root_admin_docs_match_environment_specific_counts():
    docs = "\n".join(
        Path(path).read_text(encoding="utf-8")
        for path in (
            "docs/DEPLOYMENT.md",
            "docs/GITHUB_ACTIONS.md",
            "docs/OPERATIONS.md",
        )
    )
    docs = " ".join(docs.split())

    assert "exactly 7" not in docs
    assert "STAGING_ROOT_ADMIN_EMAILS" in docs
    assert "PROD_ROOT_ADMIN_EMAILS" in docs
    assert "exactly 2" in docs
    assert "exactly 3" in docs


def test_authentication_boundary_docs_cover_current_contracts():
    auth = Path(
        "docs/security/architecture/cryptography-and-authentication.md"
    ).read_text(encoding="utf-8")
    operations = Path("docs/OPERATIONS.md").read_text(encoding="utf-8")
    auth_flat = " ".join(auth.split())

    assert "scanner-safe GET landing page" in auth
    assert "CSRF-protected POST" in auth
    assert "user-and-purpose-bound HMACs" in auth
    assert "Legacy version 1 HMAC rows are not advertised" in auth_flat
    assert "provider response `action` to exactly match" in auth_flat
    assert "same-browser acceptance session binding" in auth_flat
    assert "Retired browser-credential reset URLs are not" in auth
    assert "registered and return `404`" in auth
    assert "canonicalized before OTP issuance" in operations
    assert "temporary-email domains are rejected" in operations


def test_profile_username_and_staff_invite_docs_match_service_and_browser_contracts():
    access = Path("docs/security/architecture/access-control.md").read_text(
        encoding="utf-8"
    )
    auth = Path(
        "docs/security/architecture/cryptography-and-authentication.md"
    ).read_text(encoding="utf-8")
    operations = Path("docs/OPERATIONS.md").read_text(encoding="utf-8")
    normalized = " ".join(f"{access}\n{auth}\n{operations}".split())

    for required in (
        "Customer usernames are immutable after registration",
        "are not accepted by the profile-update service contract",
        "Phone changes require current TOTP",
        "email changes require both current TOTP and a session-bound new-email code",
        "Normal browser requests render the onboarding form",
        "Viewing the page does not consume the invite or create an account",
        "only successful workplace-code and TOTP verification activates the identity",
        "Referrer-Policy: origin",
        "fresh successful Turnstile response",
        "exactly 8 Singapore mobile digits starting with `8` or `9`",
        "recipient-facing hostname in the matching Turnstile widget's hostname allowlist",
        "delivery states `unconfirmed`, `queued`, or `failed`",
    ):
        assert required in normalized

    for stale in (
        "Username and phone changes require TOTP",
        "atomic username/email/phone commit",
        "Username and phone changes commit after valid TOTP",
    ):
        assert stale not in normalized


def test_private_admin_docs_reject_wildcard_public_https():
    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    architecture = Path(
        "docs/security/architecture/admin-and-staging-zero-trust-access.md"
    ).read_text(encoding="utf-8")

    assert "`PUBLIC_BIND_ADDRESS`" in deployment
    assert "without wildcard public listeners" in deployment
    assert "reject wildcard\nport `443`" in architecture


def test_payup_security_docs_match_current_banking_contract():
    docs = "\n".join(
        Path(path).read_text(encoding="utf-8")
        for path in (
            "docs/OPERATIONS.md",
            "docs/DEPLOYMENT.md",
            "docs/security/architecture/access-control.md",
            "docs/security/assurance/secure-coding.md",
            "docs/security/assurance/feature-security-checklist.md",
        )
    )
    docs = " ".join(docs.split())

    for required in (
        "PayUp senders must set a customer-owned PayUp display nickname",
        "confirmation page shows the source account ending, sender nickname, recipient phone number, recipient PayUp nickname",
        "Nickname audit metadata records only presence and length",
        "Invalid phone number",
        "per-customer enable flag and daily limit",
        "midnight Singapore time",
        "presets are SGD 100, 500, 1000, 3000, 5000, and 10000",
        "between SGD 100.00 and SGD 10000.00 with cents precision",
        "`payup_lookup_failure`",
        "without a routine per-transfer authenticator prompt",
        "Stale sessions and recent sensitive account changes",
        "fail closed",
        "quick-transfer and quick-daily caps",
        "recomputes at confirmation and again under the sender lock",
        "The Local Transfer daily limit remains a documented placeholder",
        "keyed verifier",
        "HMAC-SHA256 transaction hash",
        "Migration `20260703_0022` adds PayUp support",
        "Migration `20260704_0027` hardens PayUp daily-limit bounds",
        "Migration `20260705_0030` adds `users.payup_nickname`",
        "SGD 100.00 welcome credit",
        "`registration_credits` ledger",
        "`payup_pending_transfers`",
        "`transactions.transaction_type`",
        "Migration `20260703_0024` enforces exactly 12 decimal digits",
        "account numbers are exactly 12 decimal digits",
    ):
        assert required in docs

    stale_phrases = (
        "PayUp lookup requires an authenticator code",
        "Phone lookup requires TOTP before recipient name disclosure",
        "PayUp lookup reveals recipient name before MFA",
        "PayUp lookup does not require MFA",
        "PayUp lookup returns only a masked recipient identity",
        "Local Transfer daily limit is enforced",
        "transfers at least 80% of the daily limit",
        "greater than SGD 100",
    )
    for stale in stale_phrases:
        assert stale not in docs


def test_payee_cooldown_docs_cover_scheduled_transfer_boundary():
    docs = "\n".join(
        Path(path).read_text(encoding="utf-8")
        for path in (
            "docs/OPERATIONS.md",
            "docs/security/architecture/access-control.md",
        )
    )
    normalized_docs = " ".join(docs.split())
    route_text = Path("app/banking/routes.py").read_text(encoding="utf-8")
    model_text = Path("app/models.py").read_text(encoding="utf-8")

    assert "No customer scheduled-transfer executor is currently exposed" in normalized_docs
    assert "must call the same centralized payee cooldown guard before money movement" in normalized_docs
    assert "class ScheduledTransfer" not in model_text
    assert "/scheduled-transfer" not in route_text


def test_auth_schema_reset_and_customer_unlock_docs_match_current_contract():
    docs = "\n".join(
        Path(path).read_text(encoding="utf-8")
        for path in (
            "docs/DEPLOYMENT.md",
            "docs/OPERATIONS.md",
            "docs/security/architecture/access-control.md",
            "docs/security/architecture/session-management.md",
            "docs/security/governance/legacy-and-out-of-scope-technology.md",
        )
    )

    for required in (
        "reset-demo-database --target staging",
        'RESET STAGING DEMO DATABASE"',
        "reset-demo-database --target production",
        "--staging-verified --approved --backup-file",
        "exactly 12 decimal digits",
        "different active\nroot admin",
        "missing, malformed, or unsupported structured context",
        "legacy `risk_fingerprint` alone is not accepted",
        "sign in again after deployment",
        "do not relax TOTP replay checks",
        "retired URLs are unregistered",
    ):
        assert required in docs
    for stale in (
        "legacy 9-digit rows remain valid",
        "A matching legacy `risk_fingerprint` is accepted",
        "narrow\nmigration case",
        "server writes the structured context before sensitive-action",
        "disabled\ncompatibility code",
        "`staff_invites.personal_email_normalized` nullable",
    ):
        assert stale not in docs


def test_feature_security_checklist_is_indexed_and_avoids_external_overclaims():
    index = Path("docs/security/README.md").read_text(encoding="utf-8")
    checklist = Path("docs/security/assurance/feature-security-checklist.md").read_text(
        encoding="utf-8"
    )

    assert "Feature security checklist" in index
    for required in (
        "Current Feature Status",
        "PayUp",
        "Root-admin bootstrap and allowlist",
        "Staff/admin maker-checker",
        "Browser E2E",
        "do not prove live staging or production provider state",
        "stale-documentation test",
    ):
        assert required in checklist
    for forbidden in (
        "live provider state is verified",
        "branch protection is enforced",
        "SonarQube gate is passing",
    ):
        assert forbidden not in checklist


def test_audit_viewer_docs_match_simple_search_and_sgt_timestamp_contract():
    audit_docs = Path("docs/security/assurance/audit-and-alerting.md").read_text(
        encoding="utf-8"
    )
    audit_docs = " ".join(audit_docs.split())

    for required in (
        "single visible `q` search box",
        "advanced filter disclosure",
        "actor username",
        "privileged workplace email",
        "Customer personal email",
        "does not search raw unbounded metadata",
        "Visible UI timestamps display in UTC+8/SGT",
        "machine-readable UTC/ISO values remain",
    ):
        assert required in audit_docs
    for stale in (
        "readable UTC such as",
        "session reference, and numeric actor ID",
    ):
        assert stale not in audit_docs


def test_human_facing_templates_do_not_render_raw_machine_timestamps():
    timestamp_expression = re.compile(
        r"{{[^{}]*(?:\.(?:created_at|updated_at|expires_at|decided_at|"
        r"executed_at|generated_at|timestamp)(?:_utc)?\b|\|utc_iso\b)[^{}]*}}"
    )
    machine_attribute = re.compile(
        r'(?:datetime|data-[a-z0-9_-]+|value)="[^"]*$',
        re.IGNORECASE,
    )
    failures = []

    for path in Path("app/templates").rglob("*.html"):
        text = path.read_text(encoding="utf-8")
        assert ".isoformat(" not in text
        for line_number, line in enumerate(text.splitlines(), start=1):
            for match in timestamp_expression.finditer(line):
                expression = match.group(0)
                if "_display" in expression or "|sgt_datetime" in expression:
                    continue
                if machine_attribute.search(line[: match.start()]):
                    continue
                failures.append(f"{path}:{line_number}: {expression}")

    assert failures == []


def test_rate_limit_layering_docs_match_current_controls():
    access_control = Path("docs/security/architecture/access-control.md").read_text(
        encoding="utf-8"
    )
    access_control = " ".join(access_control.split())

    for required in (
        "Layered Rate-Limit Policy",
        "Cloudflare WAF/rate-limit provider evidence",
        "`sitbank_prod_auth`",
        "`sitbank_staging_login`",
        "`payee_lookup_failure`",
        "`payup_lookup_failure`",
        "Staging and production Nginx rate-limit files intentionally differ",
        "Repository tests do not claim live Cloudflare",
    ):
        assert required in access_control


def test_mfa_wrong_code_threshold_docs_match_config_defaults():
    # The documented MFA wrong-code policy must track the real config defaults
    # so the doc cannot silently keep claiming the old 5-attempt threshold. Read
    # the source defaults so the check does not depend on ambient env overrides.
    config_source = " ".join(Path("config.py").read_text(encoding="utf-8").split())
    for required in (
        'ADMIN_MFA_FAILURE_LIMIT = _int_env( "ADMIN_MFA_FAILURE_LIMIT", default="10"',
        'CUSTOMER_MFA_FAILURE_LIMIT = _int_env( "CUSTOMER_MFA_FAILURE_LIMIT", default="10"',
        'ADMIN_MFA_FAILURE_WINDOW_SECONDS = _int_env( "ADMIN_MFA_FAILURE_WINDOW_SECONDS", default="300"',
        'CUSTOMER_MFA_FAILURE_WINDOW_SECONDS = _int_env( "CUSTOMER_MFA_FAILURE_WINDOW_SECONDS", default="300"',
    ):
        assert required in config_source

    access_control = Path("docs/security/architecture/access-control.md").read_text(
        encoding="utf-8"
    )
    access_control = " ".join(access_control.split())
    for required in (
        "10 wrong codes per 5-minute window",
        "`ADMIN_MFA_FAILURE_LIMIT` and `CUSTOMER_MFA_FAILURE_LIMIT`",
        "the 11th returns `429`",
        "account-freeze backstop stays strictly above the wrong-code throttle",
    ):
        assert required in access_control


def test_setup_invite_resend_recovery_docs_match_restored_feature():
    # The stuck-setup_pending resend recovery path is a real admin route, so the
    # docs must describe it and cannot regress to claiming it was removed.
    access_control = " ".join(
        Path("docs/security/architecture/access-control.md")
        .read_text(encoding="utf-8")
        .split()
    )
    operations = " ".join(
        Path("docs/OPERATIONS.md").read_text(encoding="utf-8").split()
    )

    assert "`resend_staff_setup_invite()`" in access_control
    assert "`admin.staff_account_resend_setup`" in access_control
    assert "Resend setup invite action on the staff accounts page" in operations
    assert "without creating a second privileged identity" in access_control


def test_transaction_ledger_hmac_key_docs_keep_keyring_on_ec2():
    docs = "\n".join(
        Path(path).read_text(encoding="utf-8")
        for path in (
            "docs/GITHUB_ACTIONS.md",
            "docs/OPERATIONS.md",
        )
    )
    docs = " ".join(docs.split())

    for required in (
        "STAGING_TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID",
        "PROD_TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID",
        "/etc/sitbank-staging/secrets/transaction_ledger_hmac_keys_json",
        "/etc/sitbank/secrets/transaction_ledger_hmac_keys_json",
        "/run/secrets/transaction_ledger_hmac_keys_json",
        "starting with staging",
        "staging has passed deployment and transaction-integrity verification",
        "prints only key ids and decoded byte lengths",
        "never key material",
        "Do not paste, screenshot, commit, upload, or log key material",
        "Do not configure",
        "deployment adopts the existing EC2 secret file",
        "all key values decode to exactly 32 bytes",
        "does not generate, upload, replace, print, or bundle the keyring",
        "retain old key ids while rows signed by them remain in the database",
    ):
        assert required in docs
    assert "`STAGING_TRANSACTION_LEDGER_HMAC_KEYS_JSON`" in docs
    assert "`PROD_TRANSACTION_LEDGER_HMAC_KEYS_JSON`" in docs
    assert "Safe output looks like `2026-07-ledger-01: 32 bytes`" in docs
