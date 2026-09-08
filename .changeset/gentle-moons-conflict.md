---
'seamless-auth-api': patch
---

`POST /admin/users` answers `409` rather than `500` when the address is already taken and
the duplicate arrives as a race.

The handler looks for an existing email and then creates, which are two statements. Two
administrators creating the same address at once both pass the lookup, and so does a client
retrying a request that had already succeeded after a timeout. The loser violated the unique
index on `users.email` and was told the create failed, when in fact the account exists,
which invites another attempt that fails the same way.

The unique violation now answers the `409 { "error": "User already exists" }` the sequential
duplicate already gets. The index also covers `phone`, which the lookup never checked, so a
duplicate phone number answers `409` now instead of `500`. Any other failure still answers
`500`.
