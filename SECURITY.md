# SITBank Security Operations

## Reporting

Do not open a public issue containing credentials, personal data, exploit
details, session identifiers, or production logs. Notify the repository owner
and deployment administrator privately, preserve timestamps and affected
commit/digest identifiers, and record the response in the project security
log.

## Secret Rotation

1. Revoke the exposed credential at its source.
2. Create a replacement using a cryptographically secure generator.
3. Install it into the appropriate root-owned file under
   `/etc/sitbank/secrets`.
4. Restart through the restricted deployment/runtime command and run
   `production-check`.
5. Revoke active sessions when rotating session-signing, Flask, CSRF, MFA
   encryption, database, or Redis credentials as required by the incident.
6. Remove the secret from Git history with a coordinated history rewrite when
   it was pushed. Treat the old value as compromised even after cleanup.

Session HMAC rotation must keep the old key in
`session_hmac_keys_json` only for the approved overlap period, set the new
`SESSION_HMAC_ACTIVE_KEY_ID`, then remove the previous key after all sessions
signed by it have expired.

## Dependency Response

Dependabot pull requests are never auto-merged. Review release notes and
transitive changes, update the reviewed manifest, regenerate the applicable
hash-locked files, and require the full test, SAST, dependency review,
container, DAST, and image scan checks.

Critical advisories require immediate triage. High advisories require an owner
and target date. A runtime upgrade is kept separate from ordinary package
updates.

## Vulnerability Exceptions

An exception must be approved in the pull request and record:

- package, image component, CVE or alert identifier, and affected digest;
- why exploitation is not currently reachable or why no safe fix exists;
- compensating controls and monitoring;
- accountable owner;
- approval date and an expiry no more than 30 days later.

Expired exceptions block release. Critical image vulnerabilities are not
ignored by default, including vulnerabilities without a vendor fix.

## Deployment and Rollback

Only a protected `main` workflow may produce a trusted production signature.
The tested, scanned, signed, and deployed image digest must be identical.
Deployment accepts only the configured GHCR repository, the protected
workflow identity, a 40-character commit SHA, and an immutable SHA-256 digest.

Migrations must remain backward-compatible with the previous image. If
readiness fails, the wrapper restores the previous digest and non-secret
configuration. Database rollback follows the documented cutover procedure and
must not be improvised during an incident.

## Monitoring

Forward these sources to a protected centralized log destination:

- journald events tagged `sitbank-deploy`;
- `sitbank-container.service` and Docker container logs;
- Nginx access/error and TLS events;
- application security audit events;
- PostgreSQL and Redis authentication/availability events.

Alert on failed deployments, signature or revision mismatches, unexpected
image digests, repeated authentication lockouts, security-key counter
anomalies, and changes to root-managed secret or FIDO policy files.

## AWS OIDC and Systems Manager

The current restricted SSH deployment remains supported. The preferred next
step is GitHub OIDC federation to a narrowly scoped AWS IAM role and Systems
Manager Run Command:

- trust only `repo:WenJiangggg/SITBank:environment:production`;
- require the GitHub OIDC audience `sts.amazonaws.com`;
- allow commands only on the tagged SITBank instance and approved SSM
  document;
- do not grant general EC2, IAM, Secrets Manager, or S3 administration;
- retain the same root deployment wrapper, Cosign checks, and environment
  approval.

Remove `EC2_SSH_PRIVATE_KEY` only after the OIDC/SSM path has passed rollback
and incident-response testing.
