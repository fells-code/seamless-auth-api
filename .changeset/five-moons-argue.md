---
'seamless-auth-api': minor
---

Correlate audit events to the session they happened in.

Audit events gain `session_id`, and `GET /admin/auth-events` accepts a
`sessionId` filter, so a suspicious session can be turned into its event history
and an event traced back to the session it came from.

The session is read from the request rather than passed at each of the 135 log
call sites. The bearer middleware already sets it for any access-token call, so
authenticated events correlate without any of those sites changing, and anything
before a session exists stays null. A caller can still name a session
explicitly, which is what an administrator acting on someone else's session
needs.

The column is nullable and not backfilled. The session for historical events is
unrecoverable.

Requires `@seamless-auth/types` 0.11.0.
