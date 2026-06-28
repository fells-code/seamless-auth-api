---
'seamless-auth-api': patch
---

Env-mapped system config (e.g. `LOGIN_METHODS`) now takes effect over
migration-seeded defaults. Previously the login-policy migration hard-seeded
`login_methods` and `bootstrapSystemConfig` only seeded missing rows, so the env
var was permanently ignored. Now bootstrap re-applies env values over config that
was never changed through the admin API (`updatedBy IS NULL`), admin edits record
`updatedBy` so they are preserved, and a migration re-applies env to existing
un-edited rows.
