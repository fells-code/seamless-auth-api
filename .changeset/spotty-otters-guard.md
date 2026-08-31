---
'seamless-auth-api': minor
---

Bound how many sessions one user may hold at once.

`max_concurrent_sessions` defaults to no limit, so an instance that predates the
setting is unaffected. Unlimited is `null` rather than `0`, and `0` is refused,
because zero would otherwise read as "no sessions allowed" and lock every user
out of a deployment that meant to remove the cap. `MAX_CONCURRENT_SESSIONS`
accepts a number, or an empty value, `null`, `none` or `unlimited` for no cap,
since a deployment template cannot easily unset a variable.

At the limit a sign-in **succeeds** and the user's oldest session is revoked with
`revokedReason: 'concurrent_session_limit'`, recorded as a new `session_evicted`
auth event naming the session that ended. Refusing the new session instead would
lock a user out of the device in front of them until something they may not have
access to expires, which for the shared workstations this exists to protect is
the common case rather than the edge one.

Enforcement runs before the new session row is created, so the limit counts the
session about to exist: at a limit of 3 a user holding 3 ends up with 3, not 4.
Lowering the limit leaves users above it, and each converges on their next
sign-in, which evicts everything above the cap in one pass. It never throws: a
session that cannot be revoked is logged and the sign-in continues, because
failing an authentication over a housekeeping step is worse than briefly
exceeding the cap.

NIST 800-53 AC-10. Requires `@seamless-auth/types` 0.16.0, which publishes the
config key.
