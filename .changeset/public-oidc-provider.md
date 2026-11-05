---
'seamless-auth-api': minor
---

`GET /system-config/public` can now tell a native admin tool how to sign in through the OpenID Provider (ADR 0003). A new system config key, `oidc_cli_client_id` (seeded from `OIDC_CLI_CLIENT_ID`, or set through `PATCH /system-config/admin`), names the application. The response gains an optional `oidcProvider: { issuer, cliClientId }`, present only when the provider is on, the issuer and key are set, and that application is active and eligible for session exchange with it turned on. Setting the key to an unknown or ineligible application answers 400; later disabling the application or turning its exchange off makes the advertisement disappear. Also fixes `PATCH /system-config/admin` answering 500 when it set a nullable key such as `oidc_issuer`, `hosted_ui` or `max_concurrent_sessions` to `null`: the row is now removed, which reads back as `null`. No migration is needed. Needs the `@seamless-auth/types` release that adds these fields.
