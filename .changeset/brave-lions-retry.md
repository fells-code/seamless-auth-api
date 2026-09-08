---
'seamless-auth-api': patch
---

A double submitted registration answers `200` and continues the flow instead of `500`.

`register` checks for an existing user and then creates one, in two statements. Double
clicking Register is enough for both requests to pass the check and reach `User.create`.
The loser violated the unique index on `users.email` and fell into the catch-all, so the
person who had just created an account was told the registration failed, a
`registration_failed` event was recorded against a null user for a registration that had
succeeded, and a client that retries on `500` sent the whole flow again. The per-identity
rate limiter does not help, since five attempts per fifteen minutes does not serialise two
that arrive in the same instant.

The unique violation now re-reads the account and continues down the existing-account
path, which is what the state actually is by then: an ephemeral token and an email OTP for
the account that exists. Nothing changes for a caller that was not racing, and a violation
that is not this address, which the unique index on `phone` is the only other candidate
for, still answers `500`.
