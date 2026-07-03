# Security Rules for SITBank Agents

Use these rules for security-sensitive code, tests, docs, deployment, and operations changes.

These rules are standing policy. When drafting GitHub issues, include only the issue-specific security guardrails needed for the touched boundary. Do not paste this whole checklist into issue bodies.

## Secure design principles

Apply these principles by default:

- Defense in depth.
- Least privilege.
- Secure defaults.
- Complete mediation.
- Fail closed.
- Separation of duties.
- Explicit trust boundaries.
- Safe auditability.
- Secret minimization.
- Privacy-preserving logging.
- Configuration validation before readiness.
- Small, reviewable changes.

Do not weaken an existing security control to make implementation easier. If a control must change, the replacement must be documented, tested, and at least as secure.

## Identity and access rules

Preserve customer, staff, admin, and root-admin identity separation.

Rules:

- Customers use customer identity and customer registration flows.
- Staff, admin, and root-admin users use approved workplace-domain identities where privileged access is involved.
- Privileged identities must not depend on customer personal email.
- Root-admin allowlists must be explicit in production/admin runtime.
- Placeholder or demo root-admin identities must be rejected in production/admin runtime.
- Staff/admin/root-admin access must be authorized server-side, not only hidden in UI.
- Staff business operations and admin technical operations must remain separated.
- Manual recovery, audit-log viewing, alert management, staff management, and root-admin operations must enforce role checks server-side.
- Maker-checker or separation-of-duty controls must remain intact where implemented.

Do not allow:

- Random public domains for privileged admin identity.
- Duplicate privileged identities after normalization.
- Placeholder root-admin identities in production/admin mode.
- Customers to self-register as privileged users by using workplace domains.
- Staff to approve, recover, or modify their own linked customer identities where maker-checker separation is required.
- UI-only authorization for privileged actions.

## Authentication, sessions, MFA, and recovery

Preserve:

- Password hashing through the dedicated password hashing module.
- MFA requirements where implemented.
- CSRF protection on state-changing browser flows.
- Session integrity and session invalidation on sensitive account changes.
- Secure cookie attributes.
- Rate limiting, backoff controls, and replay protections.
- Safe password reset and recovery flows.
- Safe remember-me or token-based flows where implemented.
- Separation between TOTP, recovery codes, reset flows, and session tokens.

Rules:

- Recovery codes must be one-time use where implemented.
- Recovery and reset flows must invalidate relevant sessions and tokens.
- MFA enrollment, reset, disablement, and recovery must be audited safely.
- High-risk privileged MFA/reset operations must preserve maker-checker or admin/root-admin controls where implemented.
- Do not weaken MFA requirements to simplify login, tests, or admin access.

## Token and verifier rules

When dealing with tokens:

- Store only keyed verifiers or hashes where appropriate.
- Use sufficient entropy.
- Validate issuer, audience, expiry, not-before, signature, and intended use where applicable.
- Do not log raw tokens, token verifiers, session IDs, CSRF values, cookies, JWTs, or reset/recovery material.
- Do not expose token validation internals in user-facing errors.
- Fail closed on malformed, expired, missing, not-yet-valid, wrong-audience, wrong-issuer, or invalid tokens.

## Cryptography rules

Use dedicated, reviewed helpers for cryptography.

Rules:

- Passwords must use the dedicated password hashing implementation.
- Do not use bare SHA-256 for password hashing.
- HMAC-SHA256 is acceptable for keyed integrity/reference use when keyed with sufficient entropy and documented correctly.
- HMAC helpers must be clearly named/documented as HMAC and must not be used for password hashing.
- Do not invent new crypto protocols.
- Do not truncate authentication verifiers below the security level required by the design.
- Keep key separation, key identifiers, key rotation, and versioning behavior intact.
- Do not print key material, derived secrets, raw encrypted payloads containing sensitive plaintext, or decryption failures with sensitive context.
- Prefer constant-time comparison helpers for secret/verifier comparisons.

When a static analysis tool flags crypto, triage whether the use is password hashing, keyed HMAC, encryption, signing, or safe reference generation before changing behavior.

## Cloudflare rules

Preserve staging zero-trust boundaries:

- Cloudflare Access protects the staging hostname.
- Cloudflare Authenticated Origin Pull protects the origin from direct bypass.
- Nginx enforces origin protection.
- Flask authentication and MFA still apply after Cloudflare Access.

Rules:

- Do not expose public `/health/ready` for staging when the selected staging contract intentionally blocks it.
- Deployment readiness should use local loopback readiness when public readiness is intentionally blocked.
- Direct-origin staging requests must fail closed and must not return SITBank app content.
- Acceptable direct-origin fail-closed outcomes may include `400`, `403`, TLS client-certificate failure, or connection rejection, depending on the design.
- Do not require exact `403` unless the implementation intentionally returns exact `403`.
- Do not log Cloudflare Access JWTs, service tokens, API tokens, cookies, provider response bodies, or raw Access assertions.
- Cloudflare provider-state evidence must be sanitized.
- Cloudflare checks must fail closed if required policy evidence is missing, broad, or unsafe.
- Do not claim Cloudflare provider state is proven by repo files alone.

Cloudflare Access assertion validation must verify issuer, audience, signature, expiration, and not-before, and must fail closed when required validation cannot be performed.

## Tailscale private admin rules

Private admin access must remain private.

Preserve:

- Tailscale private admin hostname/access path where configured.
- Tailscale Serve mapping only to the loopback admin app port.
- Funnel disabled.
- Tailscale SSH disabled unless explicitly approved.
- Admin app bound to loopback/private path only.
- Public admin denial.
- Protected GitHub Environment for CI tailnet verification.
- Tailnet cleanup/logout after CI verification.

Do not expose admin routes through public Nginx, public Cloudflare Access staging, customer app routing, or unauthenticated public DNS.

Do not claim Tailscale ACL/provider state is proven by repo files alone.

## Nginx and deployment boundary rules

Preserve:

- Unknown-host denial.
- TLS policy includes.
- `server_tokens off`.
- Security headers.
- Rate limits.
- Hidden/sensitive file denial.
- Loopback-only app/admin upstreams.
- Loopback-only readiness where intended.
- Public admin denial.
- Direct-origin fail-closed behavior.

Do not add a public `proxy_pass` to an app/admin service without tests proving the appropriate boundary checks remain enforced.

## Audit and logging rules

Audit events should be useful but safe.

Safe audit metadata may include event type, safe actor/target references, route category, environment, high-level reason code, safe correlation/request ID, and sanitized provider-state summaries.

Never log, print, commit, upload, or expose:

- Passwords or real password hashes.
- Password reset tokens.
- TOTP seeds or codes.
- Recovery codes.
- Session IDs.
- CSRF tokens.
- Cookies.
- JWTs.
- Cloudflare Access assertions.
- API tokens.
- HMAC keys.
- Encryption keys.
- Private keys.
- Database URLs.
- SMTP credentials.
- Full request bodies containing sensitive data.
- Raw provider exports containing sensitive values.

User-facing errors should be safe and generic when detailed internals would help attackers. Logs may include safe reason codes, not raw secret material.

## Secret handling rules

Do not commit secrets.

Do not commit or upload `.env` files, secret files, private keys, provider tokens, database dumps with real data, production configs with secrets, raw provider exports, or screenshots containing tokens, cookies, sessions, QR codes, secret values, or private keys.

Tests must use fake values clearly marked as fake.

CI logs and artifacts must be safe by default. Do not rely only on GitHub secret masking. Sanitize before printing.

## Rate limiting, replay, and abuse controls

Preserve rate limiting, lockout, backoff, replay detection, and abuse controls where implemented.

Rules:

- Authentication, MFA, password reset, recovery, staff/admin actions, and high-risk APIs must remain rate-limited where configured.
- Replay windows and one-time token semantics must remain intact.
- Do not replace fail-closed abuse controls with best-effort logging only.
- Dedupe and alerting controls must not expose raw sensitive identifiers.

## Database and migration rules

For migrations:

- Prefer additive, safe migrations.
- Do not rewrite already-applied migration history unless explicitly safe and approved.
- Use dialect-portable patterns where tests use SQLite and production uses PostgreSQL.
- Use Alembic batch mode where SQLite table rebuilds are needed.
- Do not synthesize fake sensitive values during downgrade.
- Document irreversible/no-op downgrades when reversing would corrupt data.
- Add tests proving model and migration chain agree where practical.
- Preserve least-privilege database roles and runtime role separation.

Do not hide migration impact in issues or PRs.

## Testing and documentation rules

Security tests should include relevant positive, negative, bypass, misconfiguration, fail-closed, redaction, authorization-boundary, documentation-consistency, and workflow/static-policy behavior.

Do not require live provider credentials in normal CI tests. Use fixtures, monkeypatching, fake JWTs, fake provider responses, static workflow/config tests, and local ephemeral services where safe.

Security documentation must match implementation. Do not leave docs saying a fixed gap is still open. Do not claim a control is implemented unless code/config, tests, docs, and deployment/evidence requirements support it.

Document residual risks as accepted risk, deferred work, external provider-owned evidence, or linked follow-up issue.
