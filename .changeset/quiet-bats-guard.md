---
'seamless-auth-api': minor
---

Stop an audit write failure from silently disabling account lockout.

Failed attempts were counted by querying `auth_events`, whose writes swallow every
error. Any condition that degraded audit writes while leaving the service running
stopped failures being counted, so lockout silently stopped enforcing on every
account while authentication carried on. Disk exhaustion, a table lock, a failed
migration or connection pool exhaustion would all do it, and the absent records
are the same absent records that would have shown it happening. The practical
difference was a bounded versus an unbounded guessing attack against a numeric
OTP.

Failed attempts now go to their own `auth_failures` table, written separately from
the audit event and read only by the lockout policy, so losing the trail no longer
loses the control.

`getUserLockoutStatus` refuses rather than guessing when it cannot read the
counter: an authentication the server cannot vouch for gets the same `423` a
locked account gets.

Audit write failures are reported where monitoring already looks.
`GET /health/status` answers `200 { "message": "System up, audit degraded",
"degraded": { "audit": { … } } }` for five minutes after one. The healthy body is
unchanged, so anything already parsing it is unaffected, and the status stays
`200` because the service is still serving. That is the defined action NIST
800-53 AU-5 asks for; a log line nobody reads is not.

Audit writes themselves still do not throw. 137 call sites await them, many from
inside error handlers, so failing there would turn a bookkeeping failure into a
failed request.
