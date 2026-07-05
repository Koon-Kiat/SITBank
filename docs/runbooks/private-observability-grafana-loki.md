# Private Grafana Loki Prometheus Observability Runbook

Use this runbook to install and operate the private SITBank Grafana, Loki,
Grafana Alloy, Prometheus, and node exporter stack from `ops/observability/`.

## Access Model

- Grafana binds to `127.0.0.1:3000` on the EC2 host.
- Loki binds to `127.0.0.1:3100` on the EC2 host.
- Alloy does not publish a host port.
- Prometheus and node exporter do not publish host ports; they are reachable
  only inside the internal `sitbank-observability` Docker network.
- Grafana and Loki also join `sitbank-observability-loopback`.
  `sitbank-observability-loopback` is a bridge network used only for Docker's
  host-loopback port publishing. The private boundary is the explicit
  `127.0.0.1` host binding plus no public Nginx/Tailscale Funnel route.
- `sitbank-observability` remains an internal service network for
  container-to-container traffic between Grafana, Loki, Alloy, Prometheus, and
  node exporter.
- Normal operator access uses the private Tailscale path
  `https://admin-sitbank.tailca101b.ts.net/grafana/` mapped to local Grafana.
- SSH local port forwarding is allowed only for bootstrap or break-glass
  troubleshooting.
- No public Nginx production, staging, customer, or admin route proxies Grafana,
  Loki, or Alloy.
- Private browser access must use SSH local forwarding or a reviewed private
  Tailscale access design, not public Nginx.
- The SITBank Flask and admin runtimes do not receive Grafana credentials, Loki
  credentials, datasource credentials, or broad log-reader credentials.

## Required Host Files

Create root-owned local files before bootstrap:

```text
/etc/sitbank-observability/observability.env
/etc/sitbank-observability/secrets/grafana_admin_user
/etc/sitbank-observability/secrets/grafana_admin_password
```

`observability.env` contains non-secret immutable image references and the
approved private Grafana subpath URL:

```text
GRAFANA_IMAGE=example.invalid/grafana@sha256:<reviewed-digest>
LOKI_IMAGE=example.invalid/loki@sha256:<reviewed-digest>
ALLOY_IMAGE=example.invalid/alloy@sha256:<reviewed-digest>
PROMETHEUS_IMAGE=example.invalid/prometheus@sha256:<reviewed-digest>
NODE_EXPORTER_IMAGE=example.invalid/node-exporter@sha256:<reviewed-digest>
OBSERVABILITY_ENVIRONMENT=production
GRAFANA_PRIVATE_ROOT_URL=https://admin-sitbank.tailca101b.ts.net/grafana/
GRAFANA_SERVE_FROM_SUB_PATH=true
```

`OBSERVABILITY_ENVIRONMENT` must be `production` or `staging` for the target
host so dashboard variables keep environments separated. Do not put passwords,
tokens, API keys, webhook URLs, cookies, database URLs, or SMTP credentials in
`observability.env`. Secret files must be `root:root` mode `0600`. The
protected live verifier accepts only
`https://admin-sitbank.tailca101b.ts.net/grafana/`; do not point it at an
alternate hostname, root path, query string, custom port, or credential-bearing
URL.

Bootstrap also creates root-owned runtime state directories under
`/var/lib/sitbank-observability`. Alloy keeps only its runtime state under
`/var/lib/alloy`, backed by
`/var/lib/sitbank-observability/alloy`, so the container can remain
`read_only: true` while its remoting/config services have writable storage.

Bootstrap resolves the host `adm` and `systemd-journal` numeric GIDs with
`getent` and writes only these non-secret values to `observability.env`:

```text
ALLOY_NGINX_LOG_GROUP_ID=<host-adm-gid>
ALLOY_JOURNAL_GROUP_ID=<host-systemd-journal-gid>
```

Compose passes those values to Alloy through `group_add`. Nginx log files
remain `0640` and group-readable by `adm`; Journal files remain group-readable
by `systemd-journal`. Do not chmod host logs to `0644`, make logs
world-readable, or add broad host users/groups to work around collector access.

## Bootstrap

Initial host preparation installs the restricted root wrapper and exact sudo
rule through the existing protected application host-bootstrap path. Create
the root-managed observability secret files on EC2 without printing them:

```bash
sudo install -d -o root -g root -m 0700 /etc/sitbank-observability/secrets
sudo install -o root -g root -m 0600 /dev/null /etc/sitbank-observability/secrets/grafana_admin_user
sudo install -o root -g root -m 0600 /dev/null /etc/sitbank-observability/secrets/grafana_admin_password
sudoedit /etc/sitbank-observability/secrets/grafana_admin_user
sudoedit /etc/sitbank-observability/secrets/grafana_admin_password
sudoedit /etc/sitbank-observability/observability.env
```

For subsequent staging or production changes, run **Bootstrap private
observability on EC2** from `main` and select the matching protected
environment. The workflow uses Tailscale only for its restricted SSH path,
uploads an immutable signed archive, and invokes only
`/usr/local/sbin/sitbank-observability-bootstrap <target> <commit>`. The
wrapper verifies the archive's GitHub OIDC signer identity, trusted repository
and commit, root-owned host configuration, immutable image digests,
loopback-only ports, internal networks, Nginx route absence, Funnel denial,
and the approved private Serve mapping before calling
`bootstrap-observability-ec2`.

Each protected observability environment must provide
`OBSERVABILITY_BOOTSTRAP_TS_OAUTH_CLIENT_ID` and
`OBSERVABILITY_BOOTSTRAP_TS_OAUTH_SECRET` from a dedicated OAuth client that
may advertise only `tag:github-ci-observability-bootstrap`. Never reuse the
observability-verifier or private-admin OAuth client. The live ACL must match
the reviewed reference path
`tag:github-ci-observability-bootstrap -> tag:sitbank-observability-ec2:22`
and must not grant that source private Grafana HTTPS, unrelated destinations,
wildcards, Internet access, or Tailscale SSH.

The repository reference does not prove the live ACL, node tags, GitHub
Environment settings, host firewall, security group, or provider state.
Confirm those separately and retain only sanitized evidence.

Do not run the repository script directly for routine changes, broaden the
sudo rule, copy the checkout into a root-owned trusted path, or print secret
file contents. Keep emergency manual recovery under an approved maintenance
record with the same signed-source and precondition checks.

## Verification

### Protected Live Workflow

Run **Verify private Grafana Loki observability** from `main` after the private
observability stack, Tailscale DNS/ACLs, Grafana credentials, or datasource
provisioning changes. Select `staging` or `production`; the job uses the
matching protected GitHub Environment `observability-staging` or
`observability-production`.

Each environment must require trusted maintainer approval and restrict
deployment branches to `main`. Configure:

- `GRAFANA_PRIVATE_URL` as the private Tailscale HTTPS URL, for example
  `https://admin-sitbank.tailca101b.ts.net/grafana/`;
- optional `OBSERVABILITY_PUBLIC_PROBE_URLS` as newline-separated public
  denial probes for `/grafana`, `/loki`, `/logs`, and `/metrics`;
- `TS_OAUTH_CLIENT_ID` and `TS_OAUTH_SECRET` for a narrowly scoped Tailscale
  OAuth client tagged `tag:github-ci-observability-verify`;
- `GRAFANA_HEALTH_TOKEN` as a least-privilege Grafana service account token
  that can read `/api/health`, its own `/api/user` role, datasources, and
  datasource health.

Do not store operator passwords, browser sessions, cookies, MFA values,
Grafana admin credentials, Loki credentials, datasource passwords, raw logs, or
provider exports in GitHub secrets or artifacts. The token must not have
Grafana admin privileges. The workflow first confirms the private URL is not
reachable from the public runner, then joins Tailscale, verifies Grafana API
health with explicit HTTP `200` status validation, verifies anonymous API
denial, checks the verifier role is not admin, checks Loki datasource health
through Grafana with explicit HTTP `200` status and response-schema
validation, and verifies public SITBank paths do not expose Grafana or Loki.
Cloudflare Access challenges, generic Cloudflare edge headers, and app/Nginx
`401`, `403`, and `404` denials are valid public-denial evidence; Grafana/Loki
server headers, `x-grafana-*` or `x-loki-*` headers, `grafana_session` cookies,
and public redirects to Grafana/Loki login paths fail closed. It uploads only
`observability-evidence/private-observability.json`, a sanitized summary with
target labels, HTTP status codes, denial categories, and check names, not raw
headers, cookies, redirect URLs, or API responses.

The protected workflow is live network-path evidence. It is not a pull-request
check and must never run on forks, untrusted branches, or public GitHub-hosted
TLS jobs.

When running the verifier directly on EC2, pass `--verify-host-loopback` to
include the local Grafana and Loki readiness checks in the sanitized evidence.
Do not use that flag from a GitHub-hosted runner because `127.0.0.1` would be
the runner, not the EC2 host.

### Host Checks

```bash
sudo docker compose --env-file /etc/sitbank-observability/observability.env -f /etc/sitbank-observability/compose.yml ps
sudo docker network inspect sitbank-observability --format '{{.Internal}}'
sudo docker network inspect sitbank-observability-loopback --format '{{.Internal}}'
sudo docker inspect sitbank-grafana --format '{{json .NetworkSettings.Networks}}'
sudo docker inspect sitbank-loki --format '{{json .NetworkSettings.Networks}}'
sudo docker inspect sitbank-alloy --format '{{json .NetworkSettings.Networks}}'
sudo docker inspect sitbank-prometheus --format '{{json .NetworkSettings.Networks}}'
sudo docker inspect sitbank-node-exporter --format '{{json .NetworkSettings.Networks}}'
sudo docker port sitbank-grafana 3000/tcp
sudo docker port sitbank-loki 3100/tcp
test -z "$(sudo docker port sitbank-alloy)"
test -z "$(sudo docker port sitbank-prometheus)"
test -z "$(sudo docker port sitbank-node-exporter)"
sudo ss -ltnp | grep -E '127\.0\.0\.1:(3000|3100)([[:space:]]|$)'
sudo ss -ltnp | grep -E '0\.0\.0\.0:(3000|3100|9090|9100)|\[::\]:(3000|3100|9090|9100)|\*:(3000|3100|9090|9100)' && exit 1 || true
curl -fsSI http://127.0.0.1:3000/login
curl -fsS http://127.0.0.1:3100/ready
sudo nginx -T | grep -iE 'grafana|loki' && exit 1 || true
```

Expected:

- `sitbank-observability` reports `true` for `Internal`.
- `sitbank-observability-loopback` reports `false` for `Internal` so Docker's
  host-loopback port publishing works on EC2. This loopback bridge is not an
  ingress security boundary by itself.
- Only Grafana and Loki attach to `sitbank-observability-loopback`; Alloy
  attaches only to the internal `sitbank-observability` network.
- Grafana listens only on `127.0.0.1:3000`.
- Loki listens only on `127.0.0.1:3100`.
- Alloy, Prometheus, and node exporter publish no host listener.
- Public SITBank Nginx configs contain no Grafana or Loki route.
- The private Tailscale URL reaches Grafana only for approved operators.
- The Grafana `SITBank Prometheus` datasource points to
  `http://prometheus:9090` and the Prometheus `sitbank-node` job targets only
  `node-exporter:9100`.

### Private Tailscale Serve Browser Access Plan

The preferred convenient browser path is
`https://admin-sitbank.tailca101b.ts.net/grafana/`, served by Tailscale Serve
from the existing private admin tailnet hostname to Grafana's loopback
subpath at `http://127.0.0.1:3000/grafana`. This keeps Grafana behind the same
private tailnet access boundary as the admin app and avoids a public DNS
hostname.

Do not run these commands until an approved operator has confirmed the live
Serve configuration. Tailscale Serve supports path mounts with `--set-path` and
local reverse-proxy targets, while Tailscale Funnel is the public sharing mode;
Funnel must remain disabled. The backend target must stay on localhost.

Preflight on EC2:

```bash
sudo tailscale status --json | jq -r '.BackendState'
sudo tailscale serve status
sudo tailscale serve status --json | jq .
sudo tailscale funnel status --json | jq .
sudo /usr/local/sbin/verify-tailscale-admin-access --mode serve
curl -fsSI http://127.0.0.1:3000/login
curl -fsS http://127.0.0.1:3100/ready
sudo nginx -T | grep -iE 'grafana|loki' && exit 1 || true
```

Expected before change:

- Tailscale backend is `Running`.
- Funnel status proves Funnel is disabled.
- Existing Serve config contains the approved admin root mapping to
  `http://127.0.0.1:5002` and no unexpected public or stale handlers.
- Grafana and Loki are healthy on host loopback.
- Public Nginx still has no Grafana or Loki route.

If the current Serve status is missing the admin root mapping, contains
unexpected handlers, or does not prove Funnel is disabled, stop and repair the
admin Tailscale configuration first. Do not reset the entire Serve
configuration as a shortcut because that can remove the admin root mapping.

After updating `observability.env` to the `/grafana/` root URL and
`GRAFANA_SERVE_FROM_SUB_PATH=true`, run the protected bootstrap workflow. The
root wrapper requires the approved path mapping and rejects unexpected Serve
handlers. If the separately approved initial mapping must be established,
use:

```bash
sudo tailscale serve --bg --https=443 --set-path=/grafana http://127.0.0.1:3000/grafana
```

Verification:

```bash
sudo tailscale serve status
sudo tailscale serve status --json | jq .
sudo tailscale funnel status --json | jq .
curl -fsSI http://127.0.0.1:3000/login
curl -fsS http://127.0.0.1:3100/ready
curl -fsSI https://admin-sitbank.tailca101b.ts.net/grafana/login
curl -fsSI https://admin-sitbank.tailca101b.ts.net/loki && exit 1 || true
curl -fsSI https://admin-sitbank.tailca101b.ts.net/metrics && exit 1 || true
curl -fsSI https://sitbank.pp.ua/grafana
curl -fsSI https://sitbank.pp.ua/loki
curl -fsSI https://staging-sitbank.pp.ua/grafana
sudo docker exec sitbank-grafana sh -c 'test "${GF_SERVER_ROOT_URL}" = "https://admin-sitbank.tailca101b.ts.net/grafana/" && test "${GF_SERVER_SERVE_FROM_SUB_PATH}" = "true"'
sudo ss -ltnp | grep -E '0\.0\.0\.0:(3000|3100)|\[::\]:(3000|3100)|\*:(3000|3100)' && exit 1 || true
sudo nginx -T | grep -iE 'grafana|loki' && exit 1 || true
```

Expected after change:

- `https://admin-sitbank.tailca101b.ts.net/grafana/` reaches Grafana only from
  approved tailnet clients.
- `https://admin-sitbank.tailca101b.ts.net/` still reaches the admin app.
- `https://admin-sitbank.tailca101b.ts.net/loki` and `/metrics` do not expose
  Loki, Grafana, or Alloy.
- Grafana reports `GF_SERVER_ROOT_URL` with the `/grafana/` suffix and
  `GF_SERVER_SERVE_FROM_SUB_PATH=true`.
- Funnel remains disabled.
- Loki is not served directly.
- Public SITBank hostnames do not expose Grafana or Loki.
- No `0.0.0.0`, public IPv4, or public IPv6 listener exists for ports `3000`
  or `3100`.

Rollback the Grafana path only:

```bash
sudo tailscale serve --https=443 --set-path=/grafana off
sudo tailscale serve status
sudo /usr/local/sbin/verify-tailscale-admin-access --mode serve
```

If rollback disables normal browser access, restore the reviewed `/grafana/`
Serve path or use a separately approved temporary SSH-forwarding model for
break-glass diagnostics. Do not point the protected live verifier at an
alternate hostname or root path. Rollback must preserve the admin root Serve
mapping, leave Funnel disabled, and avoid any public Nginx or firewall change.

Alternative design: a separate private Grafana Serve hostname could avoid
path-prefix behavior but would require separate hostname, tag, ACL, workflow,
and verifier review. Do not implement that alternative without a separate
reviewed automation change.

## Approved Log Sources

Alloy collects only:

- SITBank production and staging Nginx access/error logs.
- Docker logs from containers with `sitbank.log_collect=true`.
- Allowlisted systemd journal units for SITBank security alerts, Certbot, and
  Docker operational status.

The collector labels are coarse and non-secret: `service`, `environment`,
`host_role`, and `source`.

Production and staging Nginx access logs use the reviewed
`sitbank_access_json` format from `ops/nginx/sitbank-default.conf`. It records
`message`, `event`, `service`, `result`, `status`, `method`, query-free
`route`, upstream status, and timing fields. It deliberately uses `$uri`
instead of `$request_uri` and does not log bodies, query strings, cookies,
authorization headers, CSRF values, session IDs, client IP addresses, or raw
request metadata.

Application audit and error logs expose stable dashboard fields
`event`, `environment`, `service`, `result`, `reason`, `route`, and `status`.
Use those fields for Grafana/Loki queries instead of fragile free-text
matching where structured records are available. Do not promote user IDs,
emails, IPs, request IDs, account numbers, transaction references, or session
references into labels.

Alloy reads each allowlisted systemd unit through its own
`loki.source.journal` block with a single exact `_SYSTEMD_UNIT=<unit>` match.
The journal sources read the mounted `/var/log/journal` path. Do not use `OR`
or `+` expressions in journal `matches`; Alloy supports exact field matches
and combines multiple matches as logical AND.

Alloy redacts recognized authorization, cookie, Cloudflare Access assertion,
CSRF, session, password, token, secret, TOTP, recovery-code, database URL, SMTP
credential, API key, webhook URL, Cloudflare token, Tailscale key, and SSH key
fields in header-style, JSON-field, quoted logfmt, and unquoted key/value log
lines before writing to Loki. It drops raw request-body, environment-dump, and
private-key-block lines. Treat this as defense in depth rather than approval to
collect sensitive paths or raw command transcripts.

Container log discovery currently uses the read-only host Docker socket so
Alloy can keep collection opt-in through `sitbank.log_collect=true` labels.
This is an accepted residual risk until a reviewed socket proxy or file-based
label-preserving model is implemented. Compensating controls are: the socket
mount is read-only, Alloy has no host port, `read_only: true`, `cap_drop: ALL`,
`no-new-privileges:true`, no Docker mutation endpoints are configured in Alloy,
only labelled SITBank containers are kept, logs pass through redaction before
Loki, and Grafana/Loki remain private. Remove this residual acceptance when a
least-privilege Docker API proxy or equivalent collector model is available and
tested.

Do not add home directories, shell history, environment dumps, raw command
transcripts, secret files, request bodies, authorization headers, cookies, CSRF
tokens, session IDs, reset links, TOTP values, recovery codes, database URLs,
SMTP credentials, Cloudflare tokens, Tailscale keys, SSH keys, or raw provider
exports to collector paths.

Verify only labels and sanitized samples when checking Loki. Do not paste raw
log bodies into issues or chat:

```bash
curl -fsS http://127.0.0.1:3100/loki/api/v1/label/source/values
curl -fsS http://127.0.0.1:3100/loki/api/v1/label/service/values
curl -fsG http://127.0.0.1:3100/loki/api/v1/query_range \
  --data-urlencode 'query={source="nginx_access"}' \
  --data-urlencode 'limit=5'
curl -fsG http://127.0.0.1:3100/loki/api/v1/query_range \
  --data-urlencode 'query={source="systemd"}' \
  --data-urlencode 'limit=5'
```

Expected stream labels include `source="nginx_access"`,
`source="nginx_error"`, `source="container"`, and `source="systemd"` after
matching activity occurs. Systemd streams are limited to
`sitbank-security-alerts`, `certbot`, and `docker`.

## Dashboard And Operational Alerts

The provisioned dashboard set is:

- `SITBank Operational Overview` for log ingestion, Nginx 4xx/5xx trends,
  recent Nginx requests, app/admin container failures, monitored systemd
  failures, and deployment or rollback signals.
- `SITBank Security Operations` for security alert count, deliverable alert
  count, last successful `security_alert_report`, audit chain validity, audit
  anchor status, audit anchor refresh-required/stale status, audit chain error
  count, database integrity validity, tracked `security_audit_events` count and
  max ID, and tracked `users` count and max ID.
- `SITBank HTTP Health` for status classes, 429 rate-limit responses, 403/404,
  500/502/503/504, route groups from the query-free route field, Nginx
  upstream/backend errors, and login/register/MFA route volume.
- `SITBank Infrastructure And Deployment Health` for EC2 CPU, memory, disk
  usage and disk pressure, container restart or OOM events, PostgreSQL
  connectivity/storage/connection-pressure log signals, Nginx/app/admin
  readiness checks, last deployment time and target environment, deployment
  guard failures, and deployment start/completion/rollback annotations.

Normal values are zero active alerts, zero audit-chain errors, valid database
integrity, no unexpected 5xx/502/503/504 spikes, 429s only during abusive
bursts, CPU below 80% sustained, memory below 85%, filesystems below 80%, no
repeated container restarts, and no deployment guard failures. Treat sustained
CPU above 80%, memory above 85%, disk above 80% or rapidly increasing, any
invalid audit/database integrity state, unexpected 5xx or backend errors,
readiness failures, missing deployment completion, or guard failures as
investigation triggers.

Container CPU/memory and PostgreSQL connection-count exporter metrics are not
enabled here. Those panels remain log-derived until a separate reviewed
least-privilege exporter design is implemented. Each panel describes what it
shows, when to worry, and what to check next. Variables are limited to coarse
selectors; do not add high-cardinality labels such as full paths, IP
addresses, request IDs, account IDs, user IDs, session IDs, or free-text
values.

Grafana-native alerts remain an operational follow-up until notification
contact points can be provisioned without committed webhook URLs, tokens, or
other secrets. Do not use Grafana alerts as a substitute for SITBank
`SecurityAuditEvent` alerting or the admin audit viewer.

## Retention

Loki retention is configured in `ops/observability/loki/loki.yml` with a
concrete `168h` retention period. Increase it only with a reviewed storage and
privacy decision.

## Credential Rotation And Offboarding

- Rotate Grafana admin credentials by updating the root-owned secret files and
  restarting the Grafana container.
- Remove departed operators from Grafana and from the private Tailscale access
  path.
- Rotate optional alert-delivery credentials in the provider UI or host secret
  store; do not commit them.
- Review dashboard roles so normal viewers are read-only.

## Rollback Or Disable

```bash
sudo docker compose --env-file /etc/sitbank-observability/observability.env -f /etc/sitbank-observability/compose.yml down
sudo ss -ltnp | grep -E ':(3000|3100)([[:space:]]|$)' && exit 1 || true
```

Disabling observability must not change SITBank customer, staging, or admin app
routing. The admin audit viewer remains backed by `SecurityAuditEvent`, not
Loki.

Rollback stops the containers but intentionally leaves
`/var/lib/sitbank-observability/alloy` and the Grafana/Loki state directories
in place for review or a later restart. Remove state only through a separate
approved retention decision.

The generated `ALLOY_NGINX_LOG_GROUP_ID` and `ALLOY_JOURNAL_GROUP_ID` entries
are non-secret and inert after the containers stop. If observability is
permanently disabled, remove those two lines with `sudoedit` only after the
stack is down; do not alter `/var/log/nginx` or journal file modes as part of
rollback.
