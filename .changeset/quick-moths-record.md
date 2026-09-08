---
'seamless-auth-api': patch
---

A bearer refused at the auth gate now leaves an audit record when the token was one this
server issued.

`verifyBearerAuth` refuses a request before any handler runs, and that refusal reached
the application log and nothing else, so a caller presenting the wrong kind of token at a
protected route left no durable trace. Moving passkey enrollment behind an access session
made that specific: an ephemeral token offered at `/webauthn/register/start` is the
account takeover probe the gate exists to stop, and refusing it was invisible.

The new `bearer_token_failed` event is written when the presented token verifies against
this issuer's keys but its `typ` is not the one the route requires. It carries the
expected and presented types, the matched route pattern and the token's subject, with
`userId` left null because a refused token has established no principal.

Deliberately narrower than any 401. A missing, malformed, expired or unsigned credential
costs a caller nothing to produce, and recording those would let one scanner, or one
signing key rotation, bury the rows that name a real attempt. Widening it waits on audit
retention (#173).

Nothing changes on the wire. The refusal answers the same 401 in the same place, and the
event is only visible to operators through the admin and internal event views, where
`bearer_token_failed` is a new value of the auth event type.
