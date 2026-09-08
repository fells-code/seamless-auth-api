---
'seamless-auth-api': minor
---

Passkey enrollment now requires an access session. This is a breaking change to the
WebAuthn contract.

**Why.** `/login` and `/registration/register` both mint an ephemeral token for an
account that already exists, from an email address alone, and `/webauthn/register/start`
and `/webauthn/register/finish` accepted that token. Anyone who knew an address could
enroll a credential against the account and sign in as its owner, including an account
holding `OWNER_EMAIL` admin roles, without ever seeing the OTP that went to the real
owner. Both routes now take `auth: 'access'`.

Nothing legitimate loses a path. Registration proves an address with an email OTP, and
verifying that OTP issues a session, so every shipped signup flow already holds one by
the time it offers a passkey. `/webauthn/login/start` and `/webauthn/login/finish` are
unchanged and still take a pre-auth token, because authenticating is what they are for.

**Enrollment no longer issues a session.** `/webauthn/register/finish` answered with a
new access and refresh token pair. Under an access session that would leave the caller's
existing session live and unrevoked, and count against `max_concurrent_sessions`, which
can evict the user's other devices. It now answers `200` with the credential it enrolled,
in the shape `/users/credentials` already uses, and leaves `verified` and `lastLogin`
alone since the session that authorised the request proved both.

**Upgrading, and it is lockstep.** A caller that enrolled a passkey with an ephemeral
token has to verify a factor first and enroll with the resulting session. Callers reaching
these routes through `@seamless-auth/express`, `@seamless-auth/fastify` or
`@seamless-auth/react` need the matching adapter release, which forwards the access
identity for these two routes.

There is no safe release order between the two. An older adapter sends the token this
release refuses, and a newer adapter sends one an older API refuses, so enrollment answers
`401` until both sides land. Upgrade the API and the adapter together.

The registration decoy responders are removed with the ephemeral gate. A decoy subject
can no longer reach enrollment, so there is nothing left for them to answer for.
