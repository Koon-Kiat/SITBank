# Cryptography And Authentication

This document records the cryptography and authentication controls found in the
SITBank repository. It cites repository evidence and points to the central
register when a control remains open or depends on deployment state.
Framework coverage is mapped in
`docs/security/governance/framework-control-matrix.md`, and current follow-up items remain
centralized in `docs/security/governance/security-gap-register.md`.

Category: [Security architecture](../README.md#architecture).

## Server Authentication

The repository implements HTTPS termination at Nginx, not inside Flask or
Gunicorn. The Flask apps run behind loopback Gunicorn listeners; Nginx is the
public TLS endpoint and forwards to the customer and admin apps with explicit
proxy headers.

| Environment | Hostname | TLS termination | Upstream |
| --- | --- | --- | --- |
| Production customer | `sitbank.pp.ua`; `www.sitbank.pp.ua` redirects to canonical | Nginx in `ops/nginx/sitbank-production.conf` | `http://127.0.0.1:5000` |
| Staging customer | `staging-sitbank.pp.ua` | Nginx in `ops/nginx/sitbank-staging.conf` | `http://127.0.0.1:5001` |

The client authenticates the server through the normal browser TLS certificate
chain for the relevant hostname. The repository expects Certbot/Let's Encrypt
files on the host:

```nginx
ssl_certificate /etc/letsencrypt/live/sitbank.pp.ua/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/sitbank.pp.ua/privkey.pem;
include /etc/nginx/snippets/sitbank-tls-policy.conf;
add_header Strict-Transport-Security "max-age=15552000; includeSubDomains" always;
```

Evidence:

| Control | Evidence |
| --- | --- |
| TLS server block and certificate path | `ops/nginx/sitbank-production.conf`; `ops/nginx/sitbank-staging.conf` |
| HTTP handling | Customer HTTP redirects with `return 301 https://sitbank.pp.ua$request_uri;`; `www.sitbank.pp.ua` HTTPS redirects to the canonical host; unknown public hosts fail closed in `ops/nginx/sitbank-default.conf` |
| Unknown host rejection | `ops/nginx/sitbank-default.conf` returns `444` for the default HTTP server and uses `ssl_reject_handshake on` for the default HTTPS server |
| HSTS | Production customer uses `Strict-Transport-Security "max-age=15552000; includeSubDomains"` to match the reviewed six-month Cloudflare policy; staging uses `Strict-Transport-Security "max-age=31536000"` at origin and must also expose acceptable HSTS at the Cloudflare edge; all public live TLS scan targets must stay at or above the scanner's 15552000-second minimum |
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
and OpenSSL are installed, the expected host files resolve below
`/etc/letsencrypt`, `certbot.timer` is enabled and active, and each certificate
parses with a valid `notAfter`. It rejects expired certificates, certificates
expiring within `CERTBOT_MIN_VALID_DAYS` (14 days by default), and certificates
without an exact DNS SAN for the expected hostname. CN fallback and wildcard
substitution are not accepted. Normal deployment uses this local,
network-independent mode. Operators run
`sudo /usr/local/sbin/verify-certbot-host-state --renewal-dry-run production`
after issuance or Certbot/ACME changes to perform the local checks and then
invoke the explicit network-dependent
`certbot renew --dry-run --cert-name <target-lineage>`.

## HTTPS Cipher Suites

Production and staging HTTPS server blocks include the shared
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
verifies the production customer endpoint after production deploy to complete
the release evidence. It scans `staging-sitbank.pp.ua` and
`sitbank.pp.ua` with a checksum-verified `testssl.sh` release, and operators
verify the `www.sitbank.pp.ua` redirect after certificate or Nginx changes. Each
per-target artifact retains untouched scanner JSON
as `testssl.raw.json` and a separate `testssl.json` policy copy, along with the
log, HTML, metadata, and policy findings. The policy copy changes only
testssl.sh's invalid `\,` escape in certificate subject strings to a literal
comma, then must pass `jq empty` before policy evaluation. This preserves the
Cloudflare Origin Pull CA subject as raw evidence without relaxing invalid-JSON
or TLS findings generally. The job summary records the UTC time, target,
workflow run, and result. It intentionally does not run on ordinary pull
requests because they do not create public TLS endpoints.

Production customer verification fails for SSLv2/SSLv3/
TLS 1.0/TLS 1.1, weak/NULL/anonymous/export/RC4/3DES cipher classes, missing,
disabled, or too-short HSTS, expired certificates, hostname mismatches,
untrusted or incomplete chains, and every HIGH, CRITICAL, or FATAL
`testssl.sh` finding. The Cloudflare Access-protected staging target accepts
the expected unauthenticated `302 Found` Access challenge, but still requires
TLS 1.0 and TLS 1.1 to be not offered, certificate hostname/trust and chain
checks to be OK, and TLS 1.3 to be offered. TLS 1.2 is optional for staging
compatibility. HSTS must meet the scanner minimum, expiration and insecure
redirect findings are prohibited, and final `overall_grade` must be `A` or
`A+`. `HSTS: not offered` is a failure for staging because the public
Cloudflare edge, not only origin Nginx, is part of the deployed HTTPS
boundary. `cipherlist_OBSOLETED: offered` on Cloudflare Universal SSL is
retained as review evidence; removing it requires Advanced Certificate
Manager/custom cipher suite support.
MEDIUM/LOW/INFO findings are retained for manual review. SSL Labs is optional
manual corroboration for a release, certificate renewal, edge change, or
incident record; it is not a release-blocking automation dependency.

## Server Private Key Storage

The TLS private key is expected to exist only on the deployment host under
Certbot-managed paths, for example:

| Hostname | Expected private key path |
| --- | --- |
| `sitbank.pp.ua`, `www.sitbank.pp.ua` | `/etc/letsencrypt/live/sitbank.pp.ua/privkey.pem` |
| `staging-sitbank.pp.ua` | `/etc/letsencrypt/live/staging-sitbank.pp.ua/privkey.pem` |

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

## Key Establishment And Secret Key Derivation

Communication keys are established by TLS during the HTTPS handshake. The
Flask application does not derive transport encryption keys and does not
implement custom transport encryption. With TLS 1.3, modern Nginx/OpenSSL
stacks use ephemeral key exchange for forward secrecy. The repository pins the
allowed Nginx TLS protocol and cipher policy in
`ops/nginx/sitbank-tls-policy.conf`; operators still validate the loaded
Nginx/OpenSSL behavior on the target host because the final negotiated suite is
deployment-state evidence.

Application-level secrets are loaded from environment variables or Docker
secret files. In production, `_read_secret_file()` in `config.py` requires
secret files to resolve under `/run/secrets`, rejects symlinks, rejects empty
or multiline values, and rejects placeholder values. The Compose files map
host files from `/etc/sitbank/secrets` or `/etc/sitbank-staging/secrets` into
`/run/secrets`.

| Secret or key | Purpose | Configuration evidence | Validation or rotation evidence |
| --- | --- | --- | --- |
| `SECRET_KEY` / `ADMIN_SECRET_KEY` | Flask application secret | `config.py`, `compose.prod.yml`, `compose.staging.yml` | Minimum 32 characters in production; direct value and `_FILE` are mutually exclusive |
| `WTF_CSRF_SECRET_KEY` / admin variant | Flask-WTF CSRF signing | `config.py`, `app/extensions.py`, `app/__init__.py` | Minimum 32 characters; `production-check` fails if too short or CSRF is disabled |
| `SESSION_HMAC_KEYS_JSON` / admin variant | Keyring for database session payload signatures and public references | `config.py`, `app/security/session_hmac.py` | 32-byte base64 values, active key id must exist; old keys can remain during rotation |
| `SESSION_LOOKUP_HMAC_KEY` / admin variant | HMAC of browser session IDs before database lookup | `config.py`, `app/security/sessions.py` | Must decode to exactly 32 bytes; customer and admin keys are separate |
| `MFA_KEK_KEYS_JSON` | Key-encryption keys for MFA secret envelope encryption | `config.py`, `app/security/crypto.py` | Keyring supports active id and `flask rewrap-mfa-deks` for rewrapping stored DEKs |
| `TRANSACTION_LEDGER_HMAC_KEYS_JSON` | Dedicated keyring for transaction-ledger integrity | `config.py`, `app/security/transaction_integrity.py` | 32-byte base64 values; the active id must exist and old ids remain available while rows signed by them are retained |
| `PASSWORD_PEPPER_B64` / admin variant | 32-byte pepper before PBKDF2 password hashing | `config.py`, `app/security/passwords.py` | Must decode to exactly 32 bytes |
| `SECURITY_AUDIT_HMAC_KEY` | HMAC key for audit hash-chain integrity | `config.py`, `app/security/audit.py` | Required and at least 32 characters in production; verified by `production-check` |
| SMTP credentials | Password reset and staff invite email delivery | `config.py`, `app/security/email.py`, Compose files | Production requires SMTP host, credentials, and `SMTP_USE_TLS=true` |

Transaction-ledger HMAC protects against an attacker who can modify database
rows but does not possess the separate ledger key. It is keyed integrity, not
asymmetric legal non-repudiation: an operator with both database-write access
and ledger-key access could forge a row. Separation of duties, audit-chain
evidence, root-managed key files, and access review remain required.

Tests covering key validation include
`tests/test_config.py::test_required_configuration_accepts_direct_or_file_exclusively`,
`tests/test_config.py::test_secret_file_rejects_empty_multiline_and_symlink`,
`tests/test_config.py::test_session_lookup_hmac_key_decodes_to_32_bytes`,
`tests/test_config.py::test_session_hmac_keyring_requires_active_32_byte_key`,
`tests/test_transaction_integrity.py`,
`tests/test_mfa_envelope_crypto.py::test_mfa_keyring_config_fails_closed`, and
`tests/test_deployment.py::test_container_bundle_keyring_validation_normalizes_ids_and_rejects_duplicates`.

MFA KEK rotation is an operator-run, staging-first procedure documented in
`docs/OPERATIONS.md#mfa-kek-rotation`. Operators add the new KEK id to the
root-managed `MFA_KEK_KEYS_JSON` keyring before running
`rewrap-mfa-deks --dry-run`; a missing target id fails before row writes with
`Target MFA KEK id is not configured`. Dry runs and real rewraps report only
scanned, updated, skipped, failure counts, and key ids. They must not display
KEK values, TOTP seeds, wrapped DEKs, ciphertext, nonces, recovery codes, QR
codes, or decrypted MFA material. Removing the old KEK is a separate
post-verification action after all rows are rewrapped and the rollback window
is approved closed.

## Cryptographic Algorithms

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
| Registration OTP | HMAC-SHA256 using the active session HMAC keyring | `app/auth/registration_otp.py` | Keeps OTP verification independent from the Flask cookie-signing key |
| Recovery codes | Versioned HMAC-SHA256 using the active session HMAC keyring, bound to user id and purpose | `app/auth/recovery_codes.py` | Prevents a stored verifier from being replayed for another user or purpose; legacy version 1 rows are no longer accepted and the 20260704_0027 migration consumes unused legacy rows |
| Password reset verifier | HMAC-SHA256 using the active session HMAC keyring | `app/auth/password_reset.py` | Stores reset verifier HMACs; raw verifier appears only in the emailed URL |
| Staff invite and workplace verification | HMAC-SHA256 using the active session HMAC keyring | `app/admin/services.py` | Stores invite tokens and workplace verification codes without raw values |
| Audit log chain | HMAC-SHA256 over canonical audit event JSON | `app/security/audit.py` | Makes audit event ordering and contents tamper-evident |
| TOTP MFA | RFC 6238-style TOTP with SHA-1, 6 digits, 30-second steps | `app/auth/services.py`, `app/admin/services.py` | Standard authenticator-app compatibility |
| HIBP password screening | SHA-1 k-anonymity prefix lookup | `app/security/passwords.py` | Sends only the first five SHA-1 hex characters to Have I Been Pwned; SHA-1 is not used for password storage |
| Random tokens | `secrets.token_urlsafe`, `secrets.token_hex`, `os.urandom`, `uuid.uuid4` | `app/auth/password_reset.py`, `app/admin/services.py`, `app/security/crypto.py`, `app/security/sessions.py` | Generates reset links, invites, recovery codes, envelope keys, nonces, and session IDs |

Tests include `tests/test_mfa_envelope_crypto.py`, `tests/test_db_session_integrity.py`,
`tests/test_passwords.py`, `tests/test_audit_alerting.py::test_audit_hash_chain_uses_hmac_key_and_reads_legacy_sha_rows`,
and `tests/test_password_reset.py::test_recovery_codes_are_hashed_single_use_reset_factors`.

## User Authentication

### Customer Authentication

Customer registration requires a verified personal/customer email OTP before
`register_user` creates a customer account. `app/security/identity_policy.py`
reserves configured admin workplace domains and root-admin allowlisted emails
for staff/admin/root-admin identities, so they cannot be used for customer
registration or customer profile email changes. Registration canonicalizes
configured plus aliases and dot-insensitive domains, maps configured equivalent
domains, and rejects configured temporary-email domains before OTP issuance.
The canonical value has a customer-only unique index. This is a deliberate
usability trade-off, not full anti-enumeration: the web registration-details
step gives specific per-field feedback for duplicate username and duplicate
phone number so a returning user can correct the form, while duplicate email
and every JSON API duplicate-field response remain generic and identical to
other ineligible outcomes; redacted audit reason codes retain operational
detail regardless of which surface returned the response. Evidence:
`app/auth/registration_otp.py`, `app/auth/services.py`,
`app/auth/routes.py`, and `app/web/routes.py`.

Public customer authentication entry points can require route-specific
Cloudflare Turnstile challenges when `TURNSTILE_ENABLED` and the matching route
flag are enabled. The covered customer routes are login, registration OTP
request, final registration submit, and password-reset request. Turnstile is
defense in depth only; CSRF, rate limits, password screening, MFA, sessions,
audit logging, and authorization remain enforced. In staging and production,
the verifier requires the provider response `action` to exactly match the
server-selected expected action for each protected route; missing, blank,
malformed, or mismatched actions fail closed. When `TURNSTILE_ALLOWED_HOSTNAMES`
is configured, the verifier also requires the Siteverify response `hostname`
to match one of the approved customer hostnames in every environment;
production-like deployments fail closed even when the allowlist is left
unconfigured, so a token solved against an unexpected hostname cannot satisfy
a protected route. Local and automated-test deployments remain permissive
when the allowlist is unset so fixtures do not need a hostname field. Operators
must still verify in Cloudflare that the configured Turnstile widget/site key
pair is scoped to the expected production and staging hostnames; this control
does not itself prove live Cloudflare-side domain binding.

Customer browser routes use the same branded `Too many attempts` response when
durable auth backoff, Flask-Limiter, or Nginx `limit_req` rejects a request.
Nginx renders the browser 429 from an internal location instead of proxying the
rejected request, while `/auth/*` keeps structured JSON. CSRF failures remain a
separate HTTP 400 with security-token wording and a route back to a fresh form.
No threshold, Turnstile, session, audit, or alert control is relaxed for this
presentation contract.

Customer login uses username or email plus password. Three failed customer
password attempts, or two failed privileged password attempts, lock the user
record and revoke active sessions across source IPs. Counters clear only after
the full password-plus-MFA flow succeeds; IP/principal backoff remains an
additional control. `authenticate_primary()`
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

Customer profile updates use authenticator-app TOTP as the server-selected
high-risk step-up method. Customer usernames are immutable after registration
and are not accepted by the profile-update service contract. Phone changes
commit after valid TOTP, with phone values validated as Singapore mobile
numbers. Profile email changes first send a short-lived, session-bound
verification code to the new email and keep the old email active until the
customer submits both that email code and a current TOTP code; the pending
challenge is also bound to the submitted phone by HMAC rather than storing the
raw phone or a redundant username in the browser session.

### TOTP MFA And Recovery Codes

The current MFA baseline is TOTP with recovery-code support.

The repository implements authenticator-app TOTP. TOTP secrets are generated
with `pyotp.random_base32(length=32)` and stored through AES-GCM envelope
encryption. Verification records a replay digest in `totp_replay_records`, so
the same accepted TOTP step and code cannot be replayed for the same scope.
Customer high-risk account, profile, transfer, payee, recovery-code, session,
password, MFA replacement, and top-up approval actions share the grouped
`customer_high_risk_action` replay scope, so a code accepted for one of those
workflows is stale for the others in the same TOTP step. Login, onboarding,
staff invite, admin, and reset-specific factors keep separate replay scopes.
Such a replay is rejected as stale input without consuming the durable
wrong-code or account-lock budgets; only malformed or non-matching TOTP
submissions advance those failure controls.
Initial and replacement setup secrets are displayed only on their creation
response. Pending setup is bound to the initiating session and expires under
`PENDING_MFA_MAX_AGE_SECONDS`; expired material is cleared rather than
redisplayed. Staff invite MFA setup uses the same bounded lifecycle.

Recovery codes are generated as random 16-byte values encoded as grouped hex,
stored as current-version, user-and-purpose-bound HMACs, consumed once, and
used only as explicit recovery-code factors. Legacy version 1 HMAC rows are
not advertised and are not consumable. The reset API does not accept a recovery
code through the TOTP field. Retired browser-credential reset URLs are not
registered and return `404`.

### Password Reset

Customer password reset uses a one-time `selector.verifier` URL. The selector
is stored for lookup; the verifier is stored only as an HMAC. Exchanging the
URL token requires a CSRF-protected POST from a scanner-safe GET landing page.
The POST marks the URL token exchanged before creating a short-lived
server-side reset transaction and clears the raw URL token from continued
browser flow; if the transaction is lost, the exchanged URL token cannot be
replayed and the customer must request a fresh reset. TOTP users must verify
TOTP or a separately submitted recovery code before completing reset; no-MFA
users can reset but remain in MFA-onboarding state on next login. Admin-like
accounts are blocked from the customer reset flow.

Evidence: `app/auth/password_reset.py`, `app/auth/routes.py`,
`app/web/routes.py`, and `app/models.py` (`PasswordResetToken` and
`PasswordResetTransaction`).

Tests: `tests/test_password_reset.py::test_forgot_password_response_is_generic_and_token_is_hashed`,
`tests/test_password_reset.py::test_reset_token_exchanges_once_into_tokenless_transaction`,
`tests/test_password_reset.py::test_reset_link_get_does_not_consume_token`,
`tests/test_password_reset.py::test_totp_user_must_verify_totp_before_password_reset`,
`tests/test_password_reset.py::test_recovery_codes_are_hashed_single_use_reset_factors`,
and `tests/test_password_reset.py::test_admin_like_customer_domain_reset_fails_closed`.

### Admin And Staff Authentication

The admin runtime is a separate Flask app mode selected by `admin_wsgi.py` and
`create_app(app_mode="admin")`. Admin/staff users use workplace email,
password, and mandatory TOTP. Active staff users must have `account_status`
`active`, an allowed staff account type, an email domain in
`ADMIN_ALLOWED_EMAIL_DOMAINS`, `mfa_enabled`, and
`workplace_email_verified_at`.

Staff onboarding is invite-based. Root admins create invites for `staff` or
`admin` roles only; root-admin self-service invite creation is not allowed.
Privileged staff/admin/root-admin identities use only approved workplace email
domains from `ADMIN_ALLOWED_EMAIL_DOMAINS`; staff invites are sent to the
workplace email and do not collect a personal backup email. Invite acceptance
validates the token, workplace email policy, Singapore mobile format, password
policy, optional Turnstile, workplace verification code, and TOTP setup before
activating the account. A normal browser GET renders the onboarding page while an explicit JSON
client receives the minimal API response. Viewing the page leaves the invite
pending and creates no account. Starting setup creates only a `setup_pending`
staff/admin identity and changes the invite to `totp_pending`; the invite becomes
`accepted` only after same-browser workplace-code and TOTP verification activates
that identity.
Normal staff/admin invites reject addresses in `ROOT_ADMIN_EMAILS`; root-admin
bootstrap and rotation remain separate reviewed operator paths. Invite creation,
revocation, acceptance reset, and reissue each require a fresh root-admin
high-risk TOTP code. Delivery state is stored as the allowlisted value
`unconfirmed`, `queued`, or `failed`. `queued` means SITBank handed the message
to the configured email backend; it does not prove recipient inbox delivery.
`unconfirmed` is the conservative state for migrated or otherwise unknown
handoff evidence, and `failed` records a rejected backend handoff without
provider detail. If a pending invite cannot be found by the recipient, check
spam/quarantine and SMTP configuration, then use the root-admin reissue action
to rotate the stored invite token hash and send a new invite link. If backend
handoff fails during invite creation, the invite is moved out of active pending
state so it does not block safe retry.
The public invite lookup returns only a generic valid-link message and exposes
no acceptance metadata, setup state, workplace email, role, status, user id,
counter, or lock timestamp. Invite acceptance responses are marked `no-store`
with `Referrer-Policy: origin`, so HTTPS form posts keep only origin-level
evidence for Flask-WTF SSL-strict CSRF protection while avoiding token-bearing
path disclosure in same-origin referrers. When Turnstile is enabled, the browser
setup submit remains disabled until a fresh successful Turnstile response exists
and is disabled again on expiry, timeout, error, or re-verification. The post-start verification step uses same-browser acceptance session
binding and is bound to the browser session that started setup. Repeated setup restarts are capped so an invite cannot
indefinitely reset passwords, TOTP secrets, or workplace verification codes;
locked active invites require a root-admin TOTP reset before another setup
attempt. This root-admin TOTP reset clears only pending acceptance state for an
active invite. Staff invite password fields are length-bounded at the request
schema before the service-level password policy runs. Repeated invalid TOTP or
workplace-code verification attempts also lock the active invite until a root
admin resets, revokes, or reissues it.
Stale or malformed browser invite links render a generic invite-unavailable page
instead of the private admin error page; explicit JSON clients receive only the
minimal generic error.

Evidence: `app/admin/routes.py`, `app/admin/services.py`,
`app/admin/separation.py`, `admin_wsgi.py`, `config.py`, and
`compose.prod.yml`.

Tests: `tests/test_admin_staff_invites.py::test_root_admin_can_create_hashed_staff_invite`,
`tests/test_admin_staff_invites.py::test_only_root_admin_with_totp_stepup_can_create_invites`,
`tests/test_admin_staff_invites.py::test_root_admin_can_reissue_pending_invite_with_new_token`,
`tests/test_admin_staff_invites.py::test_invite_email_failure_revokes_pending_invite_for_recovery`,
`tests/test_admin_staff_invites.py::test_browser_invite_onboarding_requires_csrf_and_activates_only_after_both_codes`,
`tests/test_admin_staff_invites.py::test_invite_info_returns_minimal_metadata_and_no_store_headers`,
`tests/test_admin_staff_invites.py::test_invite_acceptance_restart_limit_and_root_reset`,
`tests/test_admin_staff_invites.py::test_invite_acceptance_verification_is_bound_to_start_session`,
`tests/test_admin_staff_invites.py::test_invite_acceptance_verify_failures_lock_until_root_reset`,
`tests/test_admin_staff_invites.py::test_staff_invite_acceptance_activates_only_after_workplace_code_and_totp`,
`tests/test_admin_staff_invites.py::test_customer_registration_cannot_create_staff_or_admin_roles`,
and `tests/test_admin_isolation.py::test_customer_and_admin_apps_have_isolated_route_surfaces`.

## Password Storage

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
| Previous-password history | `password_history` stores retained prior hashes and `PASSWORD_HISTORY_RETENTION_COUNT` defaults to 3 |
| Forced password change | `force_password_change` blocks normal authenticated routes until password change clears the flag |
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
Password change and reset reject the current password and retained recent
password history; compromise-driven forced-change flags block normal
authenticated routes while leaving logout, recovery, MFA setup, and password
change paths available.

## Protection Against Unauthorized Access To Stored Passwords

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

Backup and database dump encryption is implemented as host-managed operational
tooling. `ops/backups/sitbank-backup-encrypted` creates custom-format
PostgreSQL dumps, keeps plaintext only in a root-owned temporary directory,
encrypts with an age public-recipient file, and writes mode `0600`
`.pgdump.age` backups under the host backup directory.
`ops/backups/sitbank-restore-preflight` checks approved operator context,
explicit environment and target database, encrypted backup permissions,
host-only decryption identity, and production confirmation before any restore
is attempted. CI-level coverage lives in `tests/test_backup_security.py`.
