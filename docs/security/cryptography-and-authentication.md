# Cryptography And Authentication

This document records the cryptography and authentication controls found in the
SITBank repository. It cites repository evidence and calls out gaps where the
repo delegates a control to deployment state or does not implement it.

## 1.1 Server Authentication

The repository implements HTTPS termination at Nginx, not inside Flask or
Gunicorn. The Flask apps run behind loopback Gunicorn listeners; Nginx is the
public TLS endpoint and forwards to the customer and admin apps with explicit
proxy headers.

| Environment | Hostname | TLS termination | Upstream |
| --- | --- | --- | --- |
| Production customer | `sitbank.duckdns.org` | Nginx in `ops/nginx/sitbank-production.conf` | `http://127.0.0.1:5000` |
| Production admin | `admin-sitbank.duckdns.org` | Nginx in `ops/nginx/sitbank-production.conf` | `http://127.0.0.1:5002` |
| Staging customer | `staging-sitbank.duckdns.org` | Nginx in `ops/nginx/sitbank-staging.conf` | `http://127.0.0.1:5001` |

The client authenticates the server through the normal browser TLS certificate
chain for the relevant hostname. The repository expects Certbot/Let's Encrypt
files on the host:

```nginx
ssl_certificate /etc/letsencrypt/live/sitbank.duckdns.org/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/sitbank.duckdns.org/privkey.pem;
include /etc/nginx/snippets/sitbank-tls-policy.conf;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

Evidence:

| Control | Evidence |
| --- | --- |
| TLS server block and certificate path | `ops/nginx/sitbank-production.conf`; `ops/nginx/sitbank-staging.conf` |
| HTTP handling | Customer HTTP redirects with `return 301 https://sitbank.duckdns.org$request_uri;`; public admin non-ACME HTTP returns `403` in `ops/nginx/sitbank-production.conf` |
| Unknown host rejection | `ops/nginx/sitbank-default.conf` returns `444` for the default HTTP server and uses `ssl_reject_handshake on` for the default HTTPS server |
| HSTS | Production uses `Strict-Transport-Security "max-age=31536000; includeSubDomains"`; staging uses `max-age=300` |
| Proxy trust boundary | `ops/nginx-proxy-headers.conf` overwrites `Host`, `X-Real-IP`, `X-Forwarded-For`, and `X-Forwarded-Proto`; `app/__init__.py` applies `ProxyFix` using `TRUSTED_PROXY_COUNT` |
| TLS policy and deployment validation | `ops/nginx/sitbank-tls-policy.conf` pins the shared TLS policy; `ops/deploy/bootstrap-container-ec2` requires the Certbot files, invokes `ops/deploy/verify-certbot-host-state`, and installs the TLS snippet before installing the production or staging Nginx site, then runs `nginx -t` before reload |
| Tests | `tests/test_deployment.py::test_nginx_default_server_is_shared_for_same_host_production_and_staging`, `tests/test_deployment.py::test_production_nginx_edge_config_enforces_network_boundary_and_limits`, `tests/test_deployment.py::test_staging_nginx_enforces_https_auth_health_and_rate_limits`, `tests/test_deployment.py::test_proxyfix_trusts_exactly_the_configured_nginx_hop` |

Short evidence for unknown-host rejection:

```nginx
server {
    listen 443 ssl http2 default_server;
    server_name _;
    ssl_reject_handshake on;
    return 444;
}
```

Certificate issuance and renewal are host-managed deployment operations. ACME
account state, certificate archives, and private keys remain on the EC2 host;
they are never stored in Git or mounted into application containers. The
read-only `ops/deploy/verify-certbot-host-state` verifier checks that Certbot
is installed, the expected host files exist, and `certbot.timer` is enabled and
active. Operators must also run `sudo certbot renew --dry-run` as the manual
renewal test.

## 1.2 HTTPS Cipher Suites

Production, production-admin, and staging HTTPS server blocks include the shared
`ops/nginx/sitbank-tls-policy.conf` policy. It explicitly enables only TLS 1.2
and TLS 1.3, prefers modern ECDHE curves, and restricts TLS 1.2 to ECDHE with
AEAD encryption:

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ecdh_curve X25519:prime256v1:secp384r1;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
ssl_prefer_server_ciphers off;
ssl_session_tickets off;
ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
```

This excludes SSLv2, SSLv3, TLS 1.0, TLS 1.1, CBC, RC4, 3DES, DES, NULL,
EXPORT, MD5, anonymous, static-RSA, and finite-field DHE cipher families.
TLS 1.3 is limited to its standard AES-GCM and ChaCha20-Poly1305 AEAD suites.
Session tickets remain disabled to reduce long-lived ticket-key exposure.

`ssl_conf_command` depends on the deployed Nginx and OpenSSL build. Operators
must run `nginx -t` and inspect the loaded configuration on the target host
before reload, then validate the externally offered suites after deployment.

The `.github/workflows/tls-scan.yml` **Live TLS scan evidence** workflow is
the primary automated external validation. It runs weekly, can be manually
dispatched after a TLS-relevant infrastructure change, and is called from the
trusted deployment workflow. It verifies staging immediately after staging
deploy (and blocks production deployment until that verification passes), then
verifies both production endpoints after production deploy to complete the
release evidence. It scans `staging-sitbank.duckdns.org`,
`sitbank.duckdns.org`, and `admin-sitbank.duckdns.org` with a checksum-verified
`testssl.sh` release, retaining JSON, log, HTML, metadata, and policy findings
as per-target GitHub Actions artifacts. The job summary records the UTC time,
target, workflow run, and result. It intentionally does not run on ordinary
pull requests because they do not create public TLS endpoints.

Verification fails for SSLv2/SSLv3/TLS 1.0/TLS 1.1, weak/NULL/anonymous/export/
RC4/3DES cipher classes, expired certificates, hostname mismatches, untrusted or
incomplete chains, and every HIGH, CRITICAL, or FATAL `testssl.sh` finding.
MEDIUM/LOW/INFO findings are retained for manual review. SSL Labs is optional
manual corroboration for a release, certificate renewal, edge change, or
incident record; it is not a release-blocking automation dependency.

## 1.3 Server Private Key Storage

The TLS private key is expected to exist only on the deployment host under
Certbot-managed paths, for example:

| Hostname | Expected private key path |
| --- | --- |
| `sitbank.duckdns.org` | `/etc/letsencrypt/live/sitbank.duckdns.org/privkey.pem` |
| `admin-sitbank.duckdns.org` | `/etc/letsencrypt/live/admin-sitbank.duckdns.org/privkey.pem` |
| `staging-sitbank.duckdns.org` | `/etc/letsencrypt/live/staging-sitbank.duckdns.org/privkey.pem` |

The private key is not committed to Git. `ops/deploy/bootstrap-container-ec2`
checks that the expected key files are readable before installing the Nginx
site, then invokes `ops/deploy/verify-certbot-host-state` before Nginx changes.
The verifier resolves each `live/.../privkey.pem` symlink with `readlink -f` and
checks the real target rather than the symlink mode. It requires a target below
`/etc/letsencrypt`, `root:root` ownership, no group write permission, and no
permissions for other users; `0600` is the normal mode. The application
containers in `compose.prod.yml` and `compose.staging.yml` mount application
secrets from `/run/secrets`, but they do not mount `/etc/letsencrypt`; only host
Nginx needs the TLS private key.

If a dedicated TLS-read group is ever necessary, it is a host-hardening change:
document its membership and Nginx privilege model, explicitly add it to the
verifier's reviewed allowlist, and use at most mode `0640`. Application users,
repository-owned paths, container mounts, world-readable keys, group-writable
keys, and world-writable keys are not acceptable.

## 1.4 Key Establishment And Secret Key Derivation

Communication keys are established by TLS during the HTTPS handshake. The
Flask application does not derive transport encryption keys and does not
implement custom transport encryption. With TLS 1.3, modern Nginx/OpenSSL
stacks use ephemeral key exchange for forward secrecy; the exact negotiated
groups and ciphers are deployment-stack behavior because cipher suites are not
explicitly pinned in this repo.

Application-level secrets are loaded from environment variables or Docker
secret files. In production, `_read_secret_file()` in `config.py` requires
secret files to resolve under `/run/secrets`, rejects symlinks, rejects empty
or multiline values, and rejects placeholder values. The Compose files map
host files from `/etc/sitbank/secrets` or `/etc/sitbank-staging/secrets` into
`/run/secrets`.

| Secret or key | Purpose | Configuration evidence | Validation or rotation evidence |
| --- | --- | --- | --- |
| `SECRET_KEY` / `ADMIN_SECRET_KEY` | Flask application secret and registration OTP HMAC key | `config.py`, `compose.prod.yml`, `compose.staging.yml` | Minimum 32 characters in production; direct value and `_FILE` are mutually exclusive |
| `WTF_CSRF_SECRET_KEY` / admin variant | Flask-WTF CSRF signing | `config.py`, `app/extensions.py`, `app/__init__.py` | Minimum 32 characters; `production-check` fails if too short or CSRF is disabled |
| `SESSION_HMAC_KEYS_JSON` / admin variant | Keyring for database session payload signatures and public references | `config.py`, `app/security/session_hmac.py` | 32-byte base64 values, active key id must exist; old keys can remain during rotation |
| `SESSION_LOOKUP_HMAC_KEY` / admin variant | HMAC of browser session IDs before database lookup | `config.py`, `app/security/sessions.py` | Must decode to exactly 32 bytes; customer and admin keys are separate |
| `MFA_KEK_KEYS_JSON` | Key-encryption keys for MFA secret envelope encryption | `config.py`, `app/security/crypto.py` | Keyring supports active id and `flask rewrap-mfa-deks` for rewrapping stored DEKs |
| `PASSWORD_PEPPER_B64` / admin variant | 32-byte pepper before PBKDF2 password hashing | `config.py`, `app/security/passwords.py` | Must decode to exactly 32 bytes |
| `SECURITY_AUDIT_HMAC_KEY` | HMAC key for audit hash-chain integrity | `config.py`, `app/security/audit.py` | Required and at least 32 characters in production; verified by `production-check` |
| SMTP credentials | Password reset and staff invite email delivery | `config.py`, `app/security/email.py`, Compose files | Production requires SMTP host, credentials, and `SMTP_USE_TLS=true` |

Tests covering key validation include
`tests/test_config.py::test_required_configuration_accepts_direct_or_file_exclusively`,
`tests/test_config.py::test_secret_file_rejects_empty_multiline_and_symlink`,
`tests/test_config.py::test_session_lookup_hmac_key_decodes_to_32_bytes`,
`tests/test_config.py::test_session_hmac_keyring_requires_active_32_byte_key`,
`tests/test_mfa_envelope_crypto.py::test_mfa_keyring_config_fails_closed`, and
`tests/test_deployment.py::test_container_bundle_keyring_validation_normalizes_ids_and_rejects_duplicates`.

## 1.5 Cryptographic Algorithms

Communication encryption is provided by HTTPS/TLS at Nginx. The Flask app does
not implement custom transport encryption. Internal cryptographic controls are
listed below.

| Purpose | Algorithm / primitive | File path | Why used |
| --- | --- | --- | --- |
| External transport | TLS 1.2 and TLS 1.3 through Nginx/OpenSSL | `ops/nginx/sitbank-production.conf`, `ops/nginx/sitbank-staging.conf` | Encrypts client/server communications and authenticates the server certificate |
| MFA secret storage | AES-256-GCM envelope encryption; random 32-byte DEK; random 12-byte nonces; KEK-wrapped DEK | `app/security/crypto.py` | Keeps stored TOTP seeds encrypted and bound to user-specific associated data |
| Session payload integrity | HMAC-SHA256 over canonical envelope including key id, payload, and binding context | `app/security/session_hmac.py`, `app/security/sessions.py` | Rejects tampered or copied database session payloads |
| Session lookup hashing | HMAC-SHA256 over opaque browser session id | `app/security/sessions.py` | Stores only lookup hashes, not raw browser session IDs |
| Password hashing | HMAC-SHA256 pepper followed by PBKDF2-HMAC-SHA256 with 600,000+ iterations, 32-byte salt, 32-byte derived key | `app/security/passwords.py` | Password storage with per-password salt and server-side pepper |
| Recovery codes | HMAC-SHA256 using the active session HMAC keyring | `app/auth/recovery_codes.py` | Stores one-time recovery-code verifiers without storing raw codes |
| Password reset verifier | HMAC-SHA256 using the active session HMAC keyring | `app/auth/password_reset.py` | Stores reset verifier HMACs; raw verifier appears only in the emailed URL |
| Staff invite and workplace verification | HMAC-SHA256 using the active session HMAC keyring | `app/admin/services.py` | Stores invite tokens and workplace verification codes without raw values |
| Audit log chain | HMAC-SHA256 over canonical audit event JSON | `app/security/audit.py` | Makes audit event ordering and contents tamper-evident |
| TOTP MFA | RFC 6238-style TOTP with SHA-1, 6 digits, 30-second steps | `app/auth/services.py`, `app/admin/services.py` | Standard authenticator-app compatibility |
| HIBP password screening | SHA-1 k-anonymity prefix lookup | `app/security/passwords.py` | Sends only the first five SHA-1 hex characters to Have I Been Pwned; SHA-1 is not used for password storage |
| Random tokens | `secrets.token_urlsafe`, `secrets.token_hex`, `os.urandom`, `uuid.uuid4` | `app/auth/password_reset.py`, `app/admin/services.py`, `app/security/crypto.py`, `app/security/sessions.py` | Generates reset links, invites, recovery codes, envelope keys, nonces, and session IDs |

Tests include `tests/test_mfa_envelope_crypto.py`, `tests/test_db_session_integrity.py`,
`tests/test_passwords.py`, `tests/test_audit_alerting.py::test_audit_hash_chain_uses_hmac_key_and_reads_legacy_sha_rows`,
and `tests/test_password_reset.py::test_recovery_codes_are_hashed_single_use_reset_factors`.

## 1.6 User Authentication

### Customer Authentication

Customer registration requires a verified SIT email OTP before `register_user`
creates a customer account. Evidence: `app/auth/registration_otp.py`,
`app/auth/services.py`, `app/auth/routes.py`, and `app/web/routes.py`.

Customer login uses username or email plus password. `authenticate_primary()`
uses a dummy password hash for unknown users to reduce user-enumeration timing
differences, returns the generic message `Invalid username or password`, and
rejects non-customer account types on the customer app. If TOTP is enabled,
password login creates a pending MFA session and the customer must complete
`/auth/mfa/verify` or `/mfa/verify`.

After first password login for a no-MFA customer, the code creates a limited
password-bootstrap session and the web/API `before_request` gates require MFA
setup before normal account access. Evidence: `app/auth/mfa_policy.py`,
`app/auth/routes.py::enforce_api_mfa_onboarding`, and
`app/web/routes.py::enforce_mfa_onboarding`.

### TOTP MFA And Recovery Codes

The current MFA baseline is TOTP with recovery-code support.

The repository implements authenticator-app TOTP. TOTP secrets are generated
with `pyotp.random_base32(length=32)` and stored through AES-GCM envelope
encryption. Verification records a replay digest in `totp_replay_records`, so
the same accepted TOTP step and code cannot be replayed for the same scope.

Recovery codes are generated as random 16-byte values encoded as grouped hex,
stored as HMACs, consumed once, and used only as TOTP recovery factors.

### Password Reset

Customer password reset uses a one-time `selector.verifier` URL. The selector
is stored for lookup; the verifier is stored only as an HMAC. Exchanging the
URL token creates a short-lived server-side reset transaction and clears the
raw URL token from continued browser flow. TOTP users must verify TOTP or a
TOTP recovery code before completing reset; no-MFA users can reset but remain
in MFA-onboarding state on next login. Admin-like accounts are blocked from
the customer reset flow.

Evidence: `app/auth/password_reset.py`, `app/auth/routes.py`,
`app/web/routes.py`, and `app/models.py` (`PasswordResetToken` and
`PasswordResetTransaction`).

Tests: `tests/test_password_reset.py::test_forgot_password_response_is_generic_and_token_is_hashed`,
`tests/test_password_reset.py::test_reset_token_exchanges_once_into_tokenless_transaction`,
`tests/test_password_reset.py::test_totp_user_must_verify_totp_before_password_reset`,
`tests/test_password_reset.py::test_recovery_codes_are_hashed_single_use_reset_factors`,
and `tests/test_password_reset.py::test_admin_like_customer_domain_reset_fails_closed`.

### Admin And Staff Authentication

The admin runtime is a separate Flask app mode selected by `admin_wsgi.py` and
`create_app(app_mode="admin")`. Admin/staff users use workplace email,
password, and mandatory TOTP. Active staff users must have `account_status`
`active`, an allowed staff account type, `mfa_enabled`, and
`workplace_email_verified_at`.

Staff onboarding is invite-based. Root admins create invites for `staff` or
`admin` roles only; root-admin self-service invite creation is not allowed.
Invite acceptance validates the token, personal and workplace email policies,
password policy, optional Turnstile, workplace verification code, and TOTP
setup before activating the account.

Evidence: `app/admin/routes.py`, `app/admin/services.py`,
`app/admin/separation.py`, `admin_wsgi.py`, `config.py`, and
`compose.prod.yml`.

Tests: `tests/test_admin_staff_invites.py::test_root_admin_can_create_hashed_staff_invite`,
`tests/test_admin_staff_invites.py::test_only_root_admin_with_totp_stepup_can_create_invites`,
`tests/test_admin_staff_invites.py::test_staff_invite_acceptance_activates_only_after_workplace_code_and_totp`,
`tests/test_admin_staff_invites.py::test_customer_registration_cannot_create_staff_or_admin_roles`,
and `tests/test_admin_isolation.py::test_customer_and_admin_apps_have_isolated_route_surfaces`.

## 1.7 Password Storage

Passwords are stored as custom PBKDF2-HMAC-SHA256 hashes in `User.password_hash`.
The format includes algorithm, version, iteration count, salt, and derived hash:

```text
osp-pbkdf2-sha256$v1$i=<iterations>$s=<salt>$h=<hash>
```

Implementation evidence:

| Control | Evidence |
| --- | --- |
| Per-password random salt | `hash_password()` uses `os.urandom(PBKDF2_SALT_BYTES)` in `app/security/passwords.py` |
| Minimum iteration count | `PASSWORD_PBKDF2_ITERATIONS` must be at least `600000` in `config.py` and `app/security/passwords.py` |
| Configured minimum length | `PASSWORD_MIN_LENGTH` defaults to 15 in production, may be explicitly lower in development/test, and is enforced by form/API validators plus `validate_password_policy()` |
| Server-side pepper | `_pbkdf2_digest()` HMACs the normalized password with `PASSWORD_PEPPER_B64` before PBKDF2 |
| Constant-time comparison | `verify_password()` uses `hmac.compare_digest()` |
| Algorithm and cost metadata | Hash string contains prefix, version, `i=`, `s=`, and `h=` fields |
| Rehash support | `password_hash_needs_rehash()` triggers rehash when stored iterations are below the current config |
| Common-password checks | Local blocklist plus HIBP range API in `validate_password_policy()` |
| Length checks before hashing | `PASSWORD_MIN_LENGTH`, `PASSWORD_MAX_CHARS`, and schema/form validators reject invalid passwords before hashing |

Tests: `tests/test_auth_registration_login.py::test_registration_hashes_password_with_pbkdf2`,
`tests/test_auth_registration_login.py::test_hash_password_uses_configured_pbkdf2_iterations`,
`tests/test_passwords.py::test_hashes_long_unicode_passwords_with_pbkdf2_and_rejects_unknown_hashes`,
`tests/test_passwords.py::test_password_hashing_normalizes_unicode_with_nfc`,
`tests/test_passwords.py::test_rejects_password_found_in_local_blocklist_without_remote_call`,
and `tests/test_passwords.py::test_sends_only_hash_prefix_with_padding_and_short_timeout`.

Passwords are not logged in plaintext by the code paths inspected. Audit
metadata sanitization redacts keys and values containing password, token,
secret, session, credential URL, webhook URL, and private-key patterns.

Current gap: full password history is not implemented. The code prevents reuse
of the current password during change/reset, but no previous-password history
table or retention policy was found.

## 1.8 Protection Against Unauthorized Access To Stored Passwords

The repository protects password hashes through application and deployment
controls:

| Control | Evidence |
| --- | --- |
| Runtime/migration role separation | `ops/postgres/init-sitbank-staging-roles.sh`, `app/ops/db_privileges.py`, `ops/container/smoke-test.sh` |
| Admin runtime role separation | `compose.prod.yml` and `compose.staging.yml` use `ADMIN_DATABASE_URL_FILE`; `app/ops/db_privileges.py::apply_admin_runtime_database_privileges` grants admin runtime access separately |
| Runtime app uses Docker secrets, not committed env files | `compose.prod.yml`, `compose.staging.yml`, `config.py`, `ops/runtime_contract.py` |
| No plaintext password logging | `app/security/audit.py` redacts sensitive metadata and log output |
| Customer/admin separation | `admin_wsgi.py`, `wsgi.py`, `app/__init__.py`, `app/admin/services.py`, `app/web/routes.py` |
| Secret scanning | `ops/security/scan_repository_secrets.py`, `tests/test_secret_scanner.py`, and CI in `.github/workflows/ci-deploy.yml` |
| Audit append-only controls | `migrations/versions/20260618_0003_audit_append_only_triggers.py`, `migrations/versions/20260618_0004_audit_truncate_trigger.py`, `app/ops/db_privileges.py` |

Tests include
`tests/test_deployment.py::test_smoke_fixture_and_deployment_wrapper_match_runtime_contract`,
`tests/test_deployment.py::test_compose_secret_mounts_match_runtime_contract`,
`tests/test_deployment.py::test_runtime_secret_inventory_matches_config_and_renderer`,
`tests/test_deployment.py`,
`tests/test_audit_metadata_sanitization.py::test_audit_event_storage_and_logs_do_not_leak_sensitive_metadata`,
and `tests/test_audit_alerting.py::test_audit_hash_chain_records_verifies_and_exports_anchor`.

Current gap: backup and database dump encryption/access handling is described
only at an operational level in `SECURITY.md`; the repo does not include an
automated backup encryption implementation or backup restore access-control
test.
