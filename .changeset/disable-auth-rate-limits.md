---
'seamless-auth-api': minor
---

Add a `DISABLE_AUTH_RATE_LIMITS` testing escape hatch.

Beyond the configurable global limiter (`RATE_LIMIT`), dedicated per-IP and
per-identity limiters guard the OTP, magic-link, registration, and OAuth routes,
plus JWKS. An automated test or conformance suite driving many of these flows from
a single IP trips them. Setting `DISABLE_AUTH_RATE_LIMITS=true` now makes every
auth limiter skip. It is refused under `NODE_ENV=production` (like
`ALLOW_UNCREDENTIALED_DELIVERY_SECRETS`), so it can never weaken a deployed server.
Defaults to off.
