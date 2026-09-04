---
'seamless-auth-api': minor
---

Make `POST /login` non-enumerable with decoy pre-auth tokens.

**Breaking behaviour change.** `POST /login` no longer returns `401`. An
identifier with no usable account, which previously meant an unknown identifier,
an unverified account, or an account with no permitted continuation method, now
gets `200` with a decoy ephemeral token: real, signed, and indistinguishable
from one issued to a genuine account.

A client that branched on `401` to mean "no such user" will now follow the normal
continuation flow instead, and the failure surfaces at the continuation step, as
a wrong OTP or an assertion that cannot verify, rather than at login. That is the
point of the change: there is no longer an answer to give. `@seamless-auth/react`
and `seamless-cli` already fall back to a default method list rather than reading
`401` as a terminal state, but any caller that special-cases it needs updating.

Returning `200` for an unknown identifier is worth nothing unless the next
request keeps the secret, so all fifteen endpoints that accept a pre-auth token
now answer for a decoy the way they answer for a real account. OTP sends report
success without sending. OTP and TOTP verifies fail the way a wrong code fails.
The magic link request returns its usual "if an account exists" body and the poll
returns `204` indefinitely. WebAuthn returns a plausible challenge, offering one
fabricated credential at login start, because a real account with no passkey
answers `401` there and an empty allow-list would have sorted the decoy into that
bucket. Policy-dependent branches are reproduced, so a deployment with `email_otp`
disabled still answers `403 login_method_disabled` for every identifier.

A decoy derives from one HMAC over the normalised identifier, keyed with the new
optional `DECOY_SUBJECT_SECRET` (falling back to `API_SERVICE_TOKEN`). The same
unknown identifier always maps to the same subject, since one that rerolled would
be an oracle by itself, and the subject is a well-formed v4 UUID that cannot be
told from a real user id without the key. Nothing is written for a decoy: they are
issued for any identifier a stranger can type, so persisting them would trade an
enumeration oracle for a way to fill the disk. There is deliberately no `decoy`
claim, since anyone can decode a JWT.

The new optional `LOGIN_RESPONSE_FLOOR_MS` (default `250`) holds every `/login`
answer to a minimum. The real path reads more tables than the decoy path, and
identical bodies arriving at measurably different times still answer the question.
Set it above the slowest real login the deployment sees, or `0` to turn it off.

`defineRoute` now refuses to register a route that accepts an ephemeral token and
declares no decoy responder, so a new pre-auth endpoint cannot silently reopen
the oracle.
