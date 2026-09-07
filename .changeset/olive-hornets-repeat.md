---
'seamless-auth-api': minor
---

Fix a set of authentication defects found in a review of `src`.

**Passkey enrolment now requires proven control of the account.**
`/webauthn/register/start` and `/webauthn/register/finish` accept an ephemeral token, and
both `/login` and `/registration/register` mint one for an account that already exists from
an email address alone. Enrolling a credential through that token was a full account
takeover of any verified account, including one holding `OWNER_EMAIL` admin roles.
Enrolment is refused with `403 { "error": "authentication_required" }` when the account is
already verified. A new account still bootstraps its first credential.

Breaking: adding a further passkey by way of `/login` no longer works, because that request
is indistinguishable from the attack. The flow has to move behind an authenticated session.

**`/webauthn/login/finish` answers a failed assertion.** `verifyAuthenticationResponse`
returns `verified: false` rather than throwing when a signature does not check out, and the
handler had no branch for it, so the request received no response at all and the connection
was held until something timed it out. It now answers `401` and records
`webauthn_login_failed`, so the attempt also reaches the lockout counter.

**A rotated session no longer revokes the chain it was rotated into.** Presenting a
pre-rotation access token, which stays valid until it expires, walked `replacedBySessionId`
forward and revoked the session that had just been issued, signing the user out everywhere
over an ordinary in-flight request. Refresh token reuse is still detected on `/refresh`,
where the reused credential is the refresh token itself.

**`/refresh` refuses a revoked user.** The session owner was loaded without the `revoked`
filter every other auth path applies, so a revoked account kept rotating refresh tokens
indefinitely and its session chain never died.

**The stored refresh token hash is verified.** `findRefreshSessionByToken` matched only the
HMAC lookup column, so the bcrypt hash was written on every rotation and never read.
Hashing also moves off the synchronous bcrypt call, which stalled the event loop for every
other request on the process during each sign-in and refresh.

**`/otp/verify-email-otp` applies the lockout policy.** It issues a session for an already
verified account, so an account locked out of `/otp/verify-login-email-otp` could still
authenticate through it. It is deliberately not gated on the login method policy: email OTP
is how registration proves an address, whether or not the deployment offers it as a way to
sign in. `/otp/verify-phone-otp` now records `verify_otp_failed`, so those attempts reach
the audit trail and the lockout counter as its three siblings already did.

**`/registration/register` no longer reveals whether an email is registered.** A mismatched
email and phone answered `409`, which told an unauthenticated caller that the address
existed and reopened on this endpoint the enumeration oracle `/login` goes to some length to
close. Every combination now answers with the same `200` shape, the mismatch is recorded in
the audit trail for operators, and a phone held by another account is never attached.

Also fixed: the JWKS handler gated on `NODE_ENV === 'development'` while the signing key
gates on `!== 'production'`, so a staging or CI instance signed with the dev key and could
not publish it; `createUser` stored the email without normalising case, creating an account
that could never sign in; the slow-down delay grew on total hits rather than the excess over
the threshold, holding the first throttled request for `delay_after` seconds and growing
without a ceiling; an unset `API_SERVICE_TOKEN` turned any request carrying the trusted
client IP headers into a 500; account deletion reported success without awaiting the
deletes; and OTP audit writes were discarded rather than awaited and logged without the user
they belonged to.
