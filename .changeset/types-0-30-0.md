---
'seamless-auth-api': minor
---

Moves to `@seamless-auth/types` 0.30.0.

- OAuth provider config is refused at request validation when `clientSecretEnv` does not end in `_CLIENT_SECRET` or a provider URL is not `http(s)`, the same rules 0.19.4 enforced after parsing. The production-only checks (https, public destinations) stay in the server.
- New system config keys `recovery_codes` (`RECOVERY_CODES`, default `{"enabled":true,"requireAtEnrollment":false}`) and `account_recovery` (`ACCOUNT_RECOVERY`, default `{"enabled":false,"delay":"24h"}`), seeded at boot and patchable. The recovery features that read them arrive in this release.
