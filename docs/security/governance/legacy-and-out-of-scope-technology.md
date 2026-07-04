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

## Removed Browser-Credential Experiment

The earlier WebAuthn/FIDO experiment has been removed from the application,
migration baseline, dependencies, templates, operational metadata, and active
tests. The retired URLs are unregistered and therefore return the normal `404`
response. There is no browser-credential compatibility data to preserve after
the authorized disposable-database reset. Reintroducing another authentication
factor requires a separate reviewed design and migration.
