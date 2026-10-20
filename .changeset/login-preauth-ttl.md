---
'seamless-auth-api': patch
---

`POST /login` now answers `ttl: 300`, the real lifetime of the pre-auth token it returns, instead of the access token lifetime. A caller that set its pre-auth cookie or a timer from `ttl` kept it for the access token TTL (often 15 minutes) while the token inside expired after 5. The signing expiry and the `ttl` on `/login` and `/registration/register` now share one constant, and decoy answers carry the same value as real accounts.
