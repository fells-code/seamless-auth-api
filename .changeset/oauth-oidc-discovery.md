---
'seamless-auth-api': minor
---

Add an inbound OAuth provider from its issuer's OpenID discovery document. `POST /system-config/oauth-providers/discover` takes the issuer, client id and client secret env, reads `/.well-known/openid-configuration`, and stores the provider with the endpoints it names. `POST /system-config/oauth-providers/:id/discovery` reads the document again, replaces the stored endpoints and drops the cached signing keys. The fetch follows the same rules as every other provider call (https and public addresses only in production, no redirects), with a 5 second timeout and a 64 KiB cap, and the document's issuer must match the one requested. Discovered documents are cached for an hour.
