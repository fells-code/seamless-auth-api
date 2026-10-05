---
'seamless-auth-api': minor
---

OAuth providers can now be OpenID Connect providers. With `issuer` and `jwksUri` set, the callback requires an ID token, verifies it (signature against the provider's published keys, issuer, audience, expiry, and the nonce bound into the signed OAuth state, asymmetric algorithms only), and reads the profile from its claims instead of calling `userInfoUrl`. A token that fails is refused with `400` and code `oauth_invalid_id_token`.

A provider with `externalIdSource` and `externalIdJsonPath` also links a first sign-in to the user imported under that source (`POST /admin/users/import`) whose external id equals that ID token claim, such as Entra ID's `oid`, so imported users can sign in through the directory they came from without relying on its email. The account is marked claimed, and a phone verified before then is removed. Requires `@seamless-auth/types` 0.24.0.
