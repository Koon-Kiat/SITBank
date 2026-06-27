# Cloudflare Operations

The executable automation stays beside this file. The canonical provisioning,
verification, origin-JWT validation, token-scope, emergency, and deployment
runbook is:

`docs/security/cloudflare-staging-access.md`

Run commands from the repository root with Python, for example:

```bash
python ops/cloudflare/provision-staging-access --plan
python ops/cloudflare/provision-staging-access --verify
```
