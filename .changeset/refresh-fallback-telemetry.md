---
'seamless-auth-api': patch
---

Remove the legacy refresh-token fallback scan.

Refresh-token lookup now resolves sessions solely by their indexed `refreshTokenLookup`
fingerprint. The compatibility path that scanned all pre-fingerprint sessions and
bcrypt-compared each hash on a lookup miss has been removed, along with its per-request
`Session.findAll` scan. Sessions created before the `refreshTokenLookup` migration are no
longer refreshable and must re-authenticate; such sessions are long past the refresh-token
TTL, so no active sessions are affected.
