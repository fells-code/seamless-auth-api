---
'seamless-auth-api': minor
---

Record who performed an administrative action.

Audit events gain `actor_user_id`. An administrator acting on someone else's
account is now recorded with the target in `user_id` and the administrator in
`actor_user_id`, so the trail no longer reads as though the user did it to
themselves. `GET /admin/auth-events` accepts an `actorUserId` filter, which
answers "what did this administrator do" rather than only "what happened to this
user".

Two administrative actions that previously wrote no audit event at all now write
one:

- Deleting a user through the admin API
- Revoking every session for a user

The user deletion is now awaited before the response, so a failure surfaces as a
500 rather than a success with the account still present, and the audit event
records a deletion that actually happened.

The column is nullable and not backfilled. The actor for historical events is
genuinely unknown, and inventing one would be worse than leaving it empty.

Requires `@seamless-auth/types` 0.10.0.
