# Operations

## Runtime Secrets

Keep root-managed secret files in `/etc/sitbank/secrets` and `/etc/sitbank-staging/secrets`. The container reads only mounted files under `/run/secrets`; long-lived application secrets are not exported into the Compose process environment.

MFA/TOTP seed encryption uses envelope encryption. Keep old KEKs in `mfa_kek_keys_json` until `rewrap-mfa-deks` has moved stored records to the new active KEK. Then update `MFA_KEK_ACTIVE_ID` and the root-managed keyring together.

## Trivy Exception

The temporary `.trivyignore` exception covers only `CVE-2026-42496` and `CVE-2026-8376` inherited from the official python:3.12 slim-trixie / Debian Trixie base image.

The app does not install Perl directly, does not invoke Perl, and does not process attacker-controlled tar archives with Perl. Debian marks `perl-base` as `Essential: yes`, so it must not be removed. Also, mixing Debian sid packages into Trixie is riskier than keeping the inherited package while monitoring for the fixed official base digest.

This exception is temporary with a review/remove-by date: 2026-06-26. The full Critical Trivy report with no ignore file and the fixable High/Critical gate must continue to run without hiding unrelated findings.

## Rollback

Application rollback restores the previous signed image digest and runtime bundle. Database rollback requires an explicit backup/restore decision because Alembic migrations must remain backward-compatible and are not automatically reversed.

## Monitoring

Alert on failed deployments, signature or revision mismatches, unexpected image digests, repeated authentication lockouts, security-key counter anomalies, and changes to root-managed secret or FIDO policy files.
