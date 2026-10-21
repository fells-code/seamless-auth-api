---
'seamless-auth-api': patch
---

OAuth provider configuration can no longer reach server secrets or internal addresses (GHSA-qx82-28gf-w744).

- `clientSecretEnv` must name an env var ending in `_CLIENT_SECRET` (for example `GOOGLE_CLIENT_SECRET`). Writes through `PATCH /system-config/admin` and `/system-config/oauth-providers` that name anything else answer `400 { "error": "Invalid OAuth provider" }` with the reasons, and a stored provider that names anything else fails at sign-in without reading the variable.
- Provider URLs must be `http(s)`. In production they must be `https`, and token, userinfo, JWKS and GitHub email requests go only to hosts that resolve to public addresses. List an on-premises IdP in the new `OAUTH_PROVIDER_PRIVATE_HOSTS`. Link-local addresses are refused even when listed.
- Provider requests no longer follow redirects.
- An `authorizationUrl` that is not `http(s)` (`https` in production) is refused when stored and when sign-in starts.

Upgrade note: rename a provider secret variable that does not end in `_CLIENT_SECRET` before upgrading, and add an internal IdP's host to `OAUTH_PROVIDER_PRIVATE_HOSTS`.
