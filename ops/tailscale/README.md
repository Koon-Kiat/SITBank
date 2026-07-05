# Tailscale Production Admin Automation

The approved primary model is private HTTPS through Tailscale Serve:

```text
approved operator device
  -> tailnet ACL
  -> https://admin-sitbank.tailca101b.ts.net/
  -> Tailscale Serve on the EC2 host
  -> http://127.0.0.1:5002
  -> Flask admin password login and TOTP
```

There is no public admin hostname. Tailscale Funnel is forbidden. The customer
app on port `5000` and staging admin on port `5003` are not exposed by this
automation. Staging private admin access is not configured; adding it requires
a separately approved hostname, ACL, script, verifier, documentation, and
tests.

## Safety Model

Normal CI performs static and stubbed tests only. Installation and
configuration run manually on the production EC2 host. Both mutating scripts
require `--confirm`; `--dry-run` performs no network, package, Tailscale, or
Serve mutation.

The scripts never enable Funnel, never accept a public bind address, and never
change Flask authentication, TOTP, CSRF, sessions, route authorization, audit
logging, Nginx, or application deployment. The canonical read-only verifier is
`ops/deploy/verify-tailscale-admin-access`; `verify-admin-access` delegates to
it so there is one verification contract.

## 1. Install

Review the non-mutating plan:

```bash
sudo /usr/local/sbin/sitbank-install-tailscale --dry-run
```

After an approved maintenance change:

```bash
sudo /usr/local/sbin/sitbank-install-tailscale --confirm
```

The installer supports Ubuntu 24.04 only. It downloads Tailscale's stable
repository key and source list over HTTPS, verifies repository-pinned SHA-256
digests, installs the authenticated package with `apt`, and enables
`tailscaled`. It does not join the tailnet.

## 2. Choose Authentication

The configure script supports three explicit modes:

- `oauth` (preferred for automation): supply `TS_OAUTH_CLIENT_ID` and
  `TS_OAUTH_SECRET`. The OAuth client needs **Keys > Auth Keys > Write** and
  must be restricted to `tag:admin-sitbank`.
- `authkey`: supply `TAILSCALE_AUTH_KEY`. Use a short-lived, one-off,
  pre-approved, tagged key where possible. Reusable keys require exceptional
  approval and vault storage.
- `interactive`: an approved tag owner completes browser authentication.

Never put a credential in a command argument, shell history, repository file,
issue, PR comment, screenshot, or log. Read it without echo, then export it
only in the root shell used for the confirmed command:

```bash
read -rp 'Tailscale OAuth client ID: ' TS_OAUTH_CLIENT_ID
read -rsp 'Tailscale secret: ' TS_OAUTH_SECRET; echo
export TS_OAUTH_CLIENT_ID TS_OAUTH_SECRET
sudo --preserve-env=TS_OAUTH_CLIENT_ID,TS_OAUTH_SECRET \
  /usr/local/sbin/sitbank-configure-tailscale-admin \
  --dry-run --auth-mode oauth
```

Dry-run does not read the credential. After approval, replace `--dry-run` with
`--confirm`, then immediately `unset TS_OAUTH_SECRET`. For auth-key mode, use
the same pattern with `TAILSCALE_AUTH_KEY` and
`--auth-mode authkey`. The script supplies secrets through an inherited
read-only file descriptor; it does not put them in process arguments or write
them to a named file.

## 3. Configure And Verify

OAuth example:

```bash
sudo --preserve-env=TS_OAUTH_CLIENT_ID,TS_OAUTH_SECRET \
  /usr/local/sbin/sitbank-configure-tailscale-admin \
  --confirm --auth-mode oauth
```

Auth-key example:

```bash
sudo --preserve-env=TAILSCALE_AUTH_KEY \
  /usr/local/sbin/sitbank-configure-tailscale-admin \
  --confirm --auth-mode authkey
```

The confirmed flow resets unsafe node flags, applies only
`tag:admin-sitbank`, refuses an existing non-empty Serve configuration,
configures HTTPS `443` to `http://127.0.0.1:5002`, and requires the canonical
preflight to pass. Verification can be repeated without credentials:

```bash
sudo /usr/local/sbin/sitbank-verify-tailscale-admin
```

SSH/port-forward remains fallback diagnostics only:

```bash
sudo /usr/local/sbin/sitbank-verify-tailscale-admin --mode ssh
```

This checks host prerequisites but does not claim a remote tunnel was tested.
The supported admin browser path remains private Serve HTTPS.

## ACL, Onboarding, And Offboarding

`acl-policy.hujson` is a non-secret least-privilege reference, not an
automatically applied policy. It grants production HTTPS only from
`group:sitbank-production-admins` and the protected
`tag:github-ci-admin-verify` identity to `tag:admin-sitbank:443`. Separate
`tag:github-ci-staging-deploy` and `tag:github-ci-prod-deploy` identities may
reach only their matching EC2 destination tag on port `22`. Cross-environment
paths are denied by omission. The separate
`tag:github-ci-observability-bootstrap` identity may reach only
`tag:sitbank-observability-ec2:22`; its bootstrap-only OAuth client must not be
shared with observability or private-admin verification and has no Grafana
HTTPS grant. The policy grants neither broad tailnet access nor Tailscale SSH.
Repository files do not prove live ACL, tag, OAuth-client, firewall,
security-group, GitHub Environment, or provider state; retain separate
sanitized evidence.

Onboarding requires a reviewed group change, approved managed device, Flask
staff invite, mandatory TOTP enrollment, successful host preflight, and a
browser test from that approved device. Offboarding requires removing the
group member, deleting or disabling the device, revoking Flask sessions and
the staff account, reviewing audit logs, and rerunning the preflight. A lost
device must be removed immediately from Tailscale; changing the ACL alone does
not erase it.

Rotate or revoke auth keys and OAuth clients in the Tailscale admin console.
Revoking a provisioning credential does not remove an enrolled node; remove
the node separately when required. Review groups, devices, tags, the OAuth
client/auth-key inventory, and retained preflight evidence at least quarterly.

## Emergency Disable

From approved break-glass host access:

```bash
sudo tailscale serve --https=443 off
sudo tailscale funnel status --json
sudo /usr/local/sbin/sitbank-verify-tailscale-admin --mode ssh
```

Then remove affected users/devices, revoke affected auth keys or OAuth
clients, revoke Flask admin sessions, disable affected staff accounts, and
preserve Tailscale and SITBank audit evidence. Stop `tailscaled` only when
private network access itself must be removed and approved break-glass access
is confirmed. Keep the admin listener on `127.0.0.1:5002` and keep Nginx free
of an admin upstream throughout recovery.

## Evidence Boundaries

The protected GitHub workflow proves private reachability from an ephemeral
tailnet node. These host scripts install/configure the EC2 node and prove its
local listener, Nginx, Serve, and Funnel posture. Neither normal CI nor these
scripts automatically applies the live ACL policy, approves devices, edits
groups, or proves offboarding; those remain operator-reviewed external state.

The canonical host verifier supports the reviewed Tailscale 1.98.x JSON shape:
`tailscale serve status --json` contains the HTTPS `TCP` and `Web` mapping, and
`tailscale funnel status --json` may return that same Serve configuration with
`AllowFunnel` omitted when Funnel is disabled. Omitted `AllowFunnel` is accepted
only with the known Serve fields; a truthy `AllowFunnel`, unknown non-empty
schema, wrong backend, extra endpoint, or unexpected handler fails closed.
Use these safe diagnostics without uploading raw provider state:

```bash
sudo tailscale serve status
sudo tailscale serve status --json | jq .
sudo tailscale funnel status --json | jq .
sudo /usr/local/sbin/verify-tailscale-admin-access --mode serve
```

The host verifier derives its hostname from the local node `DNSName`.
GitHub-hosted verification instead uses
`TAILSCALE_PRIVATE_ADMIN_HOST` from the protected `admin-tailscale` environment
as its single workflow source of truth.
