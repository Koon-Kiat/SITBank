# Operational Observability With Grafana And Loki

SITBank separates operational log search from the banking admin application.
Grafana, Loki, and Grafana Alloy are implemented as a private host-side
observability deployment for Nginx, container, deployment, systemd, and
host-operation evidence. The SITBank admin app remains a purpose-built viewer
for `SecurityAuditEvent` rows and sanitized security alert summaries only.

Category: [Security assurance](../README.md#assurance).

## Boundary

The reviewed deployment files are:

- `ops/observability/compose.observability.yml`;
- `ops/observability/loki/loki.yml`;
- `ops/observability/alloy/config.alloy`;
- `ops/observability/grafana/provisioning/datasources/loki.yml`;
- `ops/deploy/bootstrap-observability-ec2`;
- `docs/runbooks/private-observability-grafana-loki.md`.

Use Grafana and Loki for operational evidence such as:

- Nginx access and error logs for the production and staging edge;
- container stdout/stderr for the customer and admin runtimes;
- deployment wrapper, bootstrap, rollback, and migration wrapper logs;
- systemd status for SITBank services, timers, and deployment-adjacent units;
- host-side Tailscale, Cloudflare verification, Certbot, and Nginx checks when
  the collected record is sanitized and operator-approved.

Do not embed Loki or Grafana credentials in Flask, the admin app, templates,
browser JavaScript, or customer/admin runtime configuration. The banking admin
app must not become a general log browser and must not receive broad log-reader
credentials.

## Access Model

Grafana is private to approved operators. The Compose deployment binds Grafana
to `127.0.0.1:3000`, Loki to `127.0.0.1:3100`, and publishes no Alloy port.
Normal access uses a private Tailscale URL such as
`https://grafana-sitbank.tailca101b.ts.net/` mapped to local Grafana. SSH local
port forwarding is bootstrap or break-glass only, not the normal access model.

Live Grafana/Loki evidence is collected only by
`.github/workflows/observability-private-verify.yml`, a manually dispatched
`main`-only workflow protected by `observability-staging` or
`observability-production`. It joins Tailscale with the
`tag:github-ci-observability-verify` identity, uses a least-privilege Grafana
health token, and uploads only sanitized pass/fail evidence. Pull requests,
forks, public TLS scans, and untrusted branches do not receive Tailscale or
Grafana/Loki credentials.

Do not expose Grafana publicly through production, staging, customer, admin, or
unknown-host Nginx routes. Do not proxy, iframe, embed, or link authenticated
Grafana sessions through Flask or the admin runtime.

Use separate credentials for:

- Grafana administration;
- read-only dashboard viewers;
- Loki ingestion;
- any alert delivery integration.

Keep those credentials in root-owned host files, the operations secret store, or
the provider UI. The repository Compose file reads Grafana bootstrap credentials
from `/etc/sitbank-observability/secrets/*` and provisions Loki as a datasource
without committed datasource credentials. Do not commit Grafana admin
passwords, Loki tokens, API keys, datasource passwords, webhook URLs, cookies,
session values, or provider exports.
The protected live verifier's service account token is allowed only as a
GitHub Environment secret and must be least-privilege, non-admin, rotated on
operator offboarding, and excluded from artifacts and job summaries.

## Collection Guidance

Alloy uses allowlisted paths, Docker labels, and coarse labels. It collects
SITBank Nginx access/error logs, Docker logs only from containers labelled
`sitbank.log_collect=true`, and allowlisted systemd units. It does not collect
arbitrary home directories, shell history, environment dumps, raw command
transcripts, or secret files.

Recommended labels are coarse and non-secret:

- `service`: `nginx`, `sitbank-app`, `sitbank-admin`, `sitbank-deploy`,
  `sitbank-security-alerts`, or `sitbank-backup`;
- `environment`: `production` or `staging`;
- `host_role`: `edge`, `app`, or `database`;
- `source`: `nginx_access`, `nginx_error`, `container`, `systemd`, `deploy`,
  `bootstrap`, `certbot`, `tailscale`, or `cloudflare_verify`.

Sanitize before retaining or sharing evidence. Operational logs must not retain
passwords, TOTP codes, recovery codes, reset URLs, session IDs, CSRF values,
cookies, authorization headers, Cloudflare Access assertions, Tailscale keys,
Cloudflare API tokens, SSH private keys, database URLs, SMTP credentials,
webhook URLs, private keys, or raw request bodies.

Loki retention is bounded in `ops/observability/loki/loki.yml` with
`retention_enabled: true` and `retention_period: 168h`.

## Dashboards And Alerts

Grafana dashboards should focus on operational questions:

- Nginx status trends, 4xx/5xx rates, and direct-origin denial evidence;
- container restart loops, readiness failures, and deployment rollbacks;
- security alert timer failures and audit-chain verification command failures;
- Certbot renewal status and TLS edge verification failures;
- Cloudflare/Tailscale verification command outcomes without raw tokens.

Grafana alerts may notify operators about operational failure patterns, but they
do not replace SITBank `SecurityAuditEvent` alerting. Banking security
decisions, account actions, manual recovery, admin activity, audit hash-chain
verification, and safe investigation metadata remain in the application audit
and alerting path.

## Admin App Split

The admin audit viewer uses `SecurityAuditEvent` as its source of truth. It
shows safe metadata, safe source classification, request IDs, target
references, severity, actor role, and hash-chain row status. It does not query
Loki, render operational logs, or expose raw host command output.

Host-operation evidence that needs to be correlated with a banking incident
should be summarized safely by an operator. Reference the Grafana dashboard,
time window, service label, sanitized command category, outcome, and retained
evidence location. Do not paste raw logs or secret-bearing command lines into
GitHub, issues, pull requests, screenshots, docs, chat, or the admin app.

If sanitized host-operation events are later imported into
`security_audit_events`, that ingestion must be a separate reviewed design with
strict allowlisted event types, redaction tests, replay protection, and a clear
operator approval path.
