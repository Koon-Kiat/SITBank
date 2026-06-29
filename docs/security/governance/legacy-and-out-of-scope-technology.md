# Legacy And Out-Of-Scope Technology

This note centralizes historical technology context that should not be repeated
through active architecture, deployment, or operations documentation.

Category: [Security governance](../README.md#governance).

## Session Storage

Redis session storage was previously considered or documented, but the current
session source of truth is the application-owned `server_side_sessions`
PostgreSQL table. Controls tied to Redis session persistence, Redis-specific
namespaces, Redis connection settings, or payload-signature schemes for that
storage model apply only if the session storage layer changes.

Regression tests may still mention Redis to prove the runtime contract requires
the session lookup HMAC key and does not accidentally reintroduce old storage
configuration.

## Browser Credential Compatibility

WebAuthn, passkey, security-key, and FIDO-related work remains as disabled
compatibility code, historical database shape, checked-in metadata fixtures, and
regression coverage. Current user-facing MFA is TOTP with recovery-code support.
Existing browser-credential rows are retained only for inactive inventory,
audit, and manual-recovery decisions; they do not satisfy MFA, login, reset, or
step-up policy.

Regression tests may still mention these technologies to prove compatibility
endpoints fail closed, inactive credential rows cannot satisfy MFA, and retired
routes do not regain active behavior without review.
