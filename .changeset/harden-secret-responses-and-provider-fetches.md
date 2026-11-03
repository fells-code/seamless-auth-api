---
'seamless-auth-api': patch
---

Two hardening fixes from #556. Every API response now carries `Cache-Control: no-store` unless its route sets its own caching (the JWKS and the admin dashboard's hashed assets do), so tokens, client secrets from create and rotate, recovery codes and delivery payloads are never stored by a cache. Provider requests (OAuth token, userinfo and discovery, and back-channel logout) now go through the address guard in every mode: outside production, `http` and private or loopback addresses are still allowed, but link-local `169.254.0.0/16` and unspecified `0.0.0.0/8` addresses are refused whether named directly or reached through DNS.
