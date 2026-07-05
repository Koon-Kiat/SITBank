# Operational Observability With Grafana Loki And Prometheus

SITBank separates operational log search from the banking admin application.
Grafana, Loki, and Grafana Alloy are implemented alongside Prometheus and node
exporter inside the private host-side observability boundary.
Grafana, Loki, Grafana Alloy, Prometheus, and node exporter are implemented as
a private host-side observability deployment for Nginx, container, deployment,
systemd, host-resource, and host-operation evidence. The SITBank admin app
remains a purpose-built viewer for `SecurityAuditEvent` rows and sanitized
security alert summaries only.

Category: [Security assurance](../README.md#assurance).

## Boundary

The reviewed deployment files are:

- `ops/observability/compose.observability.yml`;
- `ops/observability/loki/loki.yml`;
- `ops/observability/alloy/config.alloy`;
- `ops/observability/grafana/provisioning/datasources/loki.yml`;
- `ops/observability/prometheus/prometheus.yml`;
- `ops/observability/grafana/dashboards/sitbank-operational-overview.json`;
- `ops/observability/grafana/dashboards/sitbank-security-operations.json`;
- `ops/observability/grafana/dashboards/sitbank-http-health.json`;
- `ops/observability/grafana/dashboards/sitbank-infrastructure-deployment-health.json`;
- `ops/deploy/bootstrap-observability-ec2`;
- `docs/runbooks/private-observability-grafana-loki.md`.

Use Grafana and Loki for operational evidence such as:

- Nginx access and error logs for the production and staging edge;
- container stdout/stderr for the customer and admin runtimes;
- deployment wrapper, bootstrap, rollback, and migration wrapper logs;
- systemd status for SITBank services, timers, and deployment-adjacent units;
- EC2 CPU, memory, filesystem usage, and disk pressure from the private node
  exporter through Prometheus;
- host-side Tailscale, Cloudflare verification, Certbot, and Nginx checks when
  the collected record is sanitized and operator-approved.

Do not embed Loki or Grafana credentials in Flask, the admin app, templates,
browser JavaScript, or customer/admin runtime configuration. The banking admin
app must not become a general log browser and must not receive broad log-reader
credentials.

## Access Model

Grafana is private to approved operators. The Compose deployment binds Grafana
to `127.0.0.1:3000`, Loki to `127.0.0.1:3100`, and publishes no Alloy,
Prometheus, or node-exporter host port.
Normal access uses the private Tailscale path
`https://admin-sitbank.tailca101b.ts.net/grafana/`, mapped to Grafana's
loopback subpath at `http://127.0.0.1:3000/grafana`. SSH local port forwarding
is bootstrap or break-glass only, not the normal access model.

Grafana and Loki also attach to `sitbank-observability-loopback`, a
non-internal bridge used only so Docker can publish host-loopback ports on EC2.
That bridge is not the ingress security boundary. The private boundary is the
explicit `127.0.0.1` host binding, no public Nginx route, no Tailscale Funnel,
no public firewall opening, and protected tailnet access. Alloy attaches only
to the internal `sitbank-observability` network and publishes no host port.
Prometheus and node exporter also attach only to that internal network; Grafana
reaches Prometheus over `http://prometheus:9090`, and Prometheus reaches node
exporter over `node-exporter:9100`.

Live Grafana/Loki evidence is collected only by
`.github/workflows/observability-private-verify.yml`, a manually dispatched
`main`-only workflow protected by `observability-staging` or
`observability-production`. It joins Tailscale with the
`tag:github-ci-observability-verify` identity, uses a least-privilege Grafana
health token, and uploads only sanitized pass/fail evidence. Pull requests,
forks, public TLS scans, and untrusted branches do not receive Tailscale or
Grafana/Loki credentials. The verifier supports the approved `/grafana/`
subpath and requires explicit HTTP `200` statuses plus schema validation for
private Grafana user, datasource, and Loki datasource-health responses. Loki is
checked only through Grafana's datasource API; direct private `/loki` and
`/metrics` requests must remain denied. Public denial probes fail closed when
response headers or cookies identify Grafana or Loki exposure, even on
non-`200` statuses.

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

The production and staging Nginx access logs use the committed
`sitbank_access_json` format. It records stable JSON fields such as `event`,
`service`, `result`, `status`, `method`, `route`, `upstream_status`, and
timing values. The `route` field uses Nginx `$uri`, not `$request_uri`, so
query strings are not written to the dashboard source. The format does not log
request or response bodies, cookies, authorization headers, CSRF values,
session identifiers, client IP addresses, or raw query strings.

Application audit and error logs use the same dashboard-friendly field names:
`event`, `environment`, `service`, `result`, `reason`, `route`, and `status`.
Existing safe audit fields remain available for investigation, and sensitive
metadata continues to be redacted before logging. Dashboard queries should use
stable `event`/`message` names and coarse labels; do not promote user IDs,
emails, IP addresses, request IDs, account numbers, session references, or
transaction references into Loki labels.

Container log discovery currently keeps the read-only host Docker socket so
Alloy can preserve label-based opt-in collection. This is an accepted residual
risk, not a claim that the raw Docker socket is least privilege. Compensating
controls are the read-only socket mount, no Alloy host port, `read_only: true`,
`cap_drop: ALL`, `no-new-privileges:true`, no Docker mutation endpoint usage in
Alloy configuration, opt-in SITBank labels, redaction before Loki ingestion,
and private-only Grafana/Loki access. Replace it with a reviewed socket proxy
or equivalent label-preserving model when that design is ready.

Recommended labels are coarse and non-secret:

- `service`: `nginx`, `sitbank-app`, `sitbank-admin`, `sitbank-deploy`,
  `sitbank-security-alerts`, or `sitbank-backup`;
- `environment`: `production` or `staging`;
- `host_role`: `edge`, `app`, or `database`;
- `source`: `nginx_access`, `nginx_error`, `container`, `systemd`, `deploy`,
  `bootstrap`, `certbot`, `tailscale`, or `cloudflare_verify`.

Sanitize before retaining or sharing evidence. Alloy redacts recognized
sensitive fields in header-style, JSON-field, quoted logfmt, and unquoted
key/value lines, and drops raw request-body, environment-dump, and private-key
block lines. Operational logs must not retain passwords, TOTP codes, recovery
codes, reset URLs, session IDs, CSRF values, cookies, authorization headers,
Cloudflare Access assertions, Tailscale keys, Cloudflare API tokens, SSH
private keys, database URLs, SMTP credentials, webhook URLs, private keys, or
raw request bodies.

Loki retention is bounded in `ops/observability/loki/loki.yml` with
`retention_enabled: true` and `retention_period: 168h`.

Prometheus stores private host metrics for the same 168-hour window. The
committed Prometheus config scrapes only node exporter with the
`OBSERVABILITY_ENVIRONMENT` label. The trusted observability bootstrap accepts
only `staging` or `production`, renders that label into the root-owned
Prometheus config before container startup, and rejects template paths outside
the reviewed `ops/observability/prometheus/` directory, missing files,
directories, symlinks, missing placeholders, or unresolved placeholders.
Prometheus does not depend on runtime environment expansion.
Container CPU/memory and PostgreSQL
connection-count exporter metrics are not enabled by this repository change;
the current container and PostgreSQL panels use log-derived restart,
connectivity, storage-pressure, and connection-pressure signals until a
separate least-privilege exporter design is reviewed.

## Dashboards And Alerts

Grafana dashboards should focus on operational questions:

- Nginx status trends, 4xx/5xx rates, and direct-origin denial evidence;
- container restart loops, readiness failures, and deployment rollbacks;
- security alert timer failures and audit-chain verification command failures;
- Certbot renewal status and TLS edge verification failures;
- Cloudflare/Tailscale verification command outcomes without raw tokens.

The provisioned dashboard set is:

- `SITBank Operational Overview`: log ingestion, Nginx 4xx/5xx trends, recent
  structured Nginx requests, app/admin container failures, monitored systemd
  failures, and deployment or rollback signals.
- `SITBank Security Operations`: security alert count, deliverable alert
  count, last successful `security_alert_report`, audit chain validity, audit
  anchor status/stale/refresh-required state, audit chain error count,
  database integrity validity, and tracked `security_audit_events`/`users`
  count and max ID.
- `SITBank HTTP Health`: requests by `2xx`/`3xx`/`4xx`/`5xx`, 429 rate-limit
  responses, 403/404 responses, 500/502/503/504 responses, route groups from
  the query-free `route` field, Nginx upstream/backend errors, and
  login/register/MFA route volume.
- `SITBank Infrastructure And Deployment Health`: EC2 CPU, memory, disk usage
  and pressure from node exporter; container restart or OOM signals;
  PostgreSQL connectivity/storage/connection-pressure log signals; Nginx,
  app, and admin readiness failures; last deployment time and target
  environment; deployment guard failures; and deployment annotations.

Dashboard files use the Grafana v2 Kubernetes resource envelope with
`apiVersion: dashboard.grafana.app/v2beta1`, `kind: Dashboard`, and a stable
`metadata.name` matching the file name. Export dashboard changes as a complete
V2 Resource, not as a bare `spec`, so file provisioning preserves dashboard
identity and can validate every layout reference against its panel element.

Normal healthy values are zero active security alerts, zero audit-chain errors,
valid database integrity, no sustained 5xx/502/503/504 responses, expected
429s only under abusive bursts, CPU below 80% sustained, memory below 85%,
filesystems below 80% usage, no repeated container restarts, and no deployment
guard failures. Investigate sustained CPU above 80%, memory above 85%, disk
above 80% or rapidly growing, any audit/database invalidity, any unexpected
5xx spike, repeated 429s on auth paths, stale audit anchors without a verified
append-only explanation, readiness failures, or missing deployment completion.

Variables stay coarse (`environment`, `service`, `source`, and status class
where present); do not add full paths, IP addresses, request IDs, account IDs,
user IDs, session IDs, or free-text values as Loki labels.

Grafana alerts may notify operators about operational failure patterns, but
contact points are intentionally deferred until they can be provisioned without
committed webhook URLs, tokens, or other secrets. They do not replace SITBank
`SecurityAuditEvent` alerting. Banking security decisions, account actions,
manual recovery, admin activity, audit hash-chain verification, and safe
investigation metadata remain in the application audit and alerting path.

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
