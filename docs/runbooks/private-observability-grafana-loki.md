# Private Grafana Loki Observability Runbook

Use this runbook to install and operate the private SITBank Grafana, Loki, and
Grafana Alloy stack from `ops/observability/`.

## Access Model

- Grafana binds to `127.0.0.1:3000` on the EC2 host.
- Loki binds to `127.0.0.1:3100` on the EC2 host.
- Alloy does not publish a host port.
- Grafana and Loki also join `sitbank-observability-loopback`.
  `sitbank-observability-loopback` is a bridge network used only for Docker's
  host-loopback port publishing. The private boundary is the explicit
  `127.0.0.1` host binding plus no public Nginx/Tailscale Funnel route.
- `sitbank-observability` remains an internal service network for
  container-to-container traffic.
- Normal operator access uses a private Tailscale path such as
  `https://grafana-sitbank.tailca101b.ts.net/` mapped to local Grafana.
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
private root URL only:

```text
GRAFANA_IMAGE=example.invalid/grafana@sha256:<reviewed-digest>
LOKI_IMAGE=example.invalid/loki@sha256:<reviewed-digest>
ALLOY_IMAGE=example.invalid/alloy@sha256:<reviewed-digest>
GRAFANA_PRIVATE_ROOT_URL=https://grafana-sitbank.tailca101b.ts.net/
GRAFANA_SERVE_FROM_SUB_PATH=false
```

Do not put passwords, tokens, API keys, webhook URLs, cookies, database URLs, or
SMTP credentials in `observability.env`. Secret files must be `root:root` mode
`0600`.

For the reviewed Tailscale Serve path model, change only the non-secret
Grafana URL settings before rerunning observability bootstrap:

```text
GRAFANA_PRIVATE_ROOT_URL=https://admin-sitbank.tailca101b.ts.net/grafana/
GRAFANA_SERVE_FROM_SUB_PATH=true
```

Keep `GRAFANA_SERVE_FROM_SUB_PATH=false` when Grafana is served at a private
hostname root such as `https://grafana-sitbank.tailca101b.ts.net/`.

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

From a reviewed checkout on EC2:

```bash
sudo install -d -o root -g root -m 0700 /etc/sitbank-observability/secrets
sudo install -o root -g root -m 0600 /dev/null /etc/sitbank-observability/secrets/grafana_admin_user
sudo install -o root -g root -m 0600 /dev/null /etc/sitbank-observability/secrets/grafana_admin_password
sudoedit /etc/sitbank-observability/secrets/grafana_admin_user
sudoedit /etc/sitbank-observability/secrets/grafana_admin_password
sudoedit /etc/sitbank-observability/observability.env
sudo ops/deploy/bootstrap-observability-ec2 "$(pwd)"
```

Do not print the secret file contents.

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
  `https://grafana-sitbank.tailca101b.ts.net/`;
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
health, verifies anonymous API denial, checks the verifier role is not admin,
checks Loki datasource health through Grafana, and verifies public SITBank
paths do not expose Grafana or Loki. It uploads only
`observability-evidence/private-observability.json`, a sanitized summary with
HTTP status codes and check names, not raw API responses.

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
sudo docker port sitbank-grafana 3000/tcp
sudo docker port sitbank-loki 3100/tcp
test -z "$(sudo docker port sitbank-alloy)"
sudo ss -ltnp | grep -E '127\.0\.0\.1:(3000|3100)([[:space:]]|$)'
sudo ss -ltnp | grep -E '0\.0\.0\.0:(3000|3100)|\[::\]:(3000|3100)|\*:(3000|3100)' && exit 1 || true
curl -fsSI http://127.0.0.1:3000/login
curl -fsS http://127.0.0.1:3100/ready
sudo nginx -T | grep -iE 'grafana|loki' && exit 1 || true
```

Expected:

- `sitbank-observability` reports `true` for `Internal`.
- `sitbank-observability-loopback` reports `false` for `Internal` so Docker's
  host-loopback port publishing works on EC2.
- Grafana listens only on `127.0.0.1:3000`.
- Loki listens only on `127.0.0.1:3100`.
- Alloy publishes no host listener.
- Public SITBank Nginx configs contain no Grafana or Loki route.
- The private Tailscale URL reaches Grafana only for approved operators.

### Private Tailscale Serve Browser Access Plan

The preferred convenient browser path is
`https://admin-sitbank.tailca101b.ts.net/grafana/`, served by Tailscale Serve
from the existing private admin tailnet hostname to Grafana's loopback
listener at `http://127.0.0.1:3000`. This keeps Grafana behind the same private
tailnet access boundary as the admin app and avoids a public DNS hostname.

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
`GRAFANA_SERVE_FROM_SUB_PATH=true`, rerun
`sudo ops/deploy/bootstrap-observability-ec2 "$(pwd)"`, then add the path
mapping:

```bash
sudo tailscale serve --bg --https=443 --set-path=/grafana http://127.0.0.1:3000
```

Verification:

```bash
sudo tailscale serve status
sudo tailscale serve status --json | jq .
sudo tailscale funnel status --json | jq .
curl -fsSI http://127.0.0.1:3000/login
curl -fsS http://127.0.0.1:3100/ready
curl -fsSI https://admin-sitbank.tailca101b.ts.net/grafana/login
curl -fsSI https://sitbank.pp.ua/grafana
curl -fsSI https://sitbank.pp.ua/loki
curl -fsSI https://staging-sitbank.pp.ua/grafana
sudo ss -ltnp | grep -E '0\.0\.0\.0:(3000|3100)|\[::\]:(3000|3100)|\*:(3000|3100)' && exit 1 || true
sudo nginx -T | grep -iE 'grafana|loki' && exit 1 || true
```

Expected after change:

- `https://admin-sitbank.tailca101b.ts.net/grafana/` reaches Grafana only from
  approved tailnet clients.
- `https://admin-sitbank.tailca101b.ts.net/` still reaches the admin app.
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

Then set `GRAFANA_PRIVATE_ROOT_URL` back to the reviewed private hostname root
or temporary SSH-forwarding URL model, set `GRAFANA_SERVE_FROM_SUB_PATH=false`,
and rerun observability bootstrap. Rollback must preserve the admin root Serve
mapping, leave Funnel disabled, and avoid any public Nginx or firewall change.

Alternative design: a separate private `grafana-sitbank.tailca101b.ts.net`
Serve hostname avoids path-prefix behavior but requires separate hostname/tag
and ACL review. Do not implement that alternative without a separate reviewed
automation change.

## Approved Log Sources

Alloy collects only:

- SITBank production and staging Nginx access/error logs.
- Docker logs from containers with `sitbank.log_collect=true`.
- Allowlisted systemd journal units for SITBank security alerts, Certbot, and
  Docker operational status.

The collector labels are coarse and non-secret: `service`, `environment`,
`host_role`, and `source`.

Alloy reads each allowlisted systemd unit through its own
`loki.source.journal` block with a single exact `_SYSTEMD_UNIT=<unit>` match.
The journal sources read the mounted `/var/log/journal` path. Do not use `OR`
or `+` expressions in journal `matches`; Alloy supports exact field matches
and combines multiple matches as logical AND.

Alloy redacts recognized authorization, cookie, CSRF, session, password,
token, secret, TOTP, recovery-code, database URL, SMTP credential, API key,
webhook URL, Cloudflare token, Tailscale key, and SSH key fields before writing
to Loki, and drops raw request-body, environment-dump, and private-key-block
lines. Treat this as defense in depth rather than approval to collect sensitive
paths or raw command transcripts.

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
