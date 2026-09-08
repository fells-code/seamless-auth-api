---
'seamless-auth-api': patch
---

Refresh token reuse detection can no longer be defeated by racing it.

Rotation read the session, checked it had not already been rotated, created the replacement
and linked the two, in four statements with no transaction, row lock or conditional write.
Two refreshes carrying the same token both passed the check and both wrote the link, and
the second write won. Both callers ended up with working refresh tokens, and one
replacement was live while reachable from nothing, so the chain revocation that reuse
detection triggers walked straight past it. Someone who copied a refresh token and raced
the legitimate client kept a session that the revocation triggered by that theft could not
reach, until its own absolute expiry.

The link is now claimed conditional on it still being unset, in one statement the database
serialises. The rotation that loses revokes the replacement it made, reloads the session so
the chain walk follows the link the winner wrote, revokes the chain from there and answers
`401 refresh_token_reused`, which is what an already rotated token has always answered.

Two legitimate refreshes racing each other now end the session chain, the same as
presenting a rotated token twice in sequence. A client that fires concurrent refreshes of a
single token will sign its user out.
