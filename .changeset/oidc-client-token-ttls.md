---
'seamless-auth-api': minor
---

Client metadata for the OpenID Provider service now carries an application's `accessTokenTtlSeconds`, `idTokenTtlSeconds` and `refreshTokenTtlSeconds` as `urn:seamless:access_token_ttl`, `urn:seamless:id_token_ttl` and `urn:seamless:refresh_token_ttl` (`@seamless-auth/types` 0.34.0-next.4). They were stored and editable through the admin routes but never reached the provider, so they had no effect. Unset values are left out and the provider's defaults apply.
