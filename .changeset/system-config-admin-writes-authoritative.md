---
'seamless-auth-api': minor
---

Make admin system-config writes authoritative so they survive a restart.

Env-mapped `system_config` rows are re-seeded from their environment variable on
every boot for any row whose `updatedBy` is `NULL`. Admin console writes went
through the access-token path, which never populated `updatedBy` (only the
service-token path did), so a change made in the console (for example adding an
OAuth provider or enabling the `oauth` login method) was silently reverted on the
next restart, contradicting the documented contract.

The whole-config `PATCH /system-config/admin` and the per-provider
`/system-config/oauth-providers` endpoints now record the acting admin's id in
`updatedBy` on the access-token path, in addition to the existing service-token
path, so an admin change is genuinely authoritative and is no longer overwritten
from env. Boot now also logs a warning when it overwrites a stored value that
differs from the env-derived one, so the reseed is no longer silent.
`docs/configuration.md` is updated to describe the real precedence.
