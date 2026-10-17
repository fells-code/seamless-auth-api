---
'seamless-auth-api': minor
---

The server refuses to start in development mode on a deployment reachable from outside.

Anything other than `NODE_ENV=production` turns on per-instance signing keys, the `/docs` explorer, fallback development secrets and the rate limit and conformance escape hatches. When `ISSUER` or any `APP_ORIGINS` entry is not local (`localhost`, `*.localhost`, `*.test`, a single-label name, or a loopback or private address), boot now stops with an error naming each one. The published image sets `NODE_ENV=production` and is unaffected; the bundled compose file and the CLI's local stacks are local and keep working.

Set `SEAMLESS_ALLOW_INSECURE_DEV=true` to run development mode on such a host on purpose. It logs a warning, and `/health/status` reports `degraded.insecureDevelopmentMode: true`. `degraded.audit` is now optional in that response, since an instance can be degraded for either reason.
