---
'seamless-auth-api': patch
---

`GET /sessions` lists only the sessions a user can still use.

Refreshing rotates a session into a new row and marks the old one with
`replacedBySessionId`, but never revokes it, and an expired session is never revoked
either. The list filtered on `revokedAt` alone, so every refresh added a row and a user
who kept one browser signed in for a few days saw a dozen or more sessions for it. The
list now applies the same conditions as the admin session list and the concurrent session
policy: not revoked, not replaced, and within both its absolute and idle expiry.
