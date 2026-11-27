---
'seamless-auth-api': minor
---

The OIDC edge contract is now version 4 (`@seamless-auth/types` 0.41). `/oidc/sign` accepts `grantType: refresh_token` with the sign-in grant it continues in `originGrantType`, and applies the device-grant rules (ADR 0001, D10) to a refresh of a device approval. The client must still hold both grants. An OpenID Provider service on contract 3 refuses to start against this API, so upgrade `@seamless-auth/oidc-provider` together with the API.
