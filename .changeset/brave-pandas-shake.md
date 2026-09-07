---
'seamless-auth-api': minor
---

Fix a second set of defects found in a review of `src`.

**TOTP step-up had no brute-force control at all.** Three controls exist and none
applied to `/totp/verify-mfa`. It checked no lockout, recorded `mfa_otp_failed`, which was
absent from the lockout failure types so the counter never moved, and sat on the one router
that carried no rate limiting. Under the global limiter alone that is roughly 72,000 guesses
a day against three accepted counters in a million, so anyone holding a valid access token
could expect to land a step-up code within days. Step-up gates device replacement recovery,
which strips passkeys and disables TOTP. The lockout policy now binds there, a failed second
factor counts toward it, and every TOTP route that accepts a code carries the same per-IP and
per-identity limiters the other code-checking endpoints use.

**Refresh tokens no longer go through bcrypt.** A refresh token is 32 random bytes, so a work
factor bought no resistance and cost roughly half a second of CPU per refresh across a hash
and a compare. The keyed fingerprint in `refreshTokenLookup` is what authenticates it, and it
is now compared in constant time after the lookup. `refreshTokenHash` is no longer written or
read; a migration drops its `NOT NULL` rather than dropping the column, so a rolling deploy
where older instances still write it keeps working, and a later release removes it.

**`sessions.userId` is indexed.** Every other table queried by user had one. This table did
not, and it is read by user on every sign-in for the concurrent session limit, on every
session list and logout-all, and by four admin handlers, against a table that gains a row on
each rotation and is never pruned.

**The dashboard's active session count meant something.** It filtered only on `revokedAt`
being null, and rotation leaves the superseded row unrevoked, so the number counted every
session a user had ever refreshed into existence and only ever grew. It now applies the same
three conditions every other active-session query uses. The passkey count also matches its
event type exactly instead of by `LIKE` wildcard.

**The security anomaly query is bounded.** It selected every failure and suspicious event in
a 24 hour window with no limit, and `request_suspicious` is recorded for every unmatched
route, so a scanner alone could make that set arbitrarily large. It now returns the most
recent 200.

**Direct messaging keys off the right environment check.** `shouldBypassDirectMessaging`
tested `NODE_ENV === 'development'`, so a staging, CI or unset environment tried to reach a
real provider and failed the request that triggered it. It now asks whether this is
production, like every other environment gate. The messaging service is also built once
rather than per message, which was constructing a provider client per channel on every OTP.

**TOTP enrollment no longer accumulates pending secrets.** Each start inserted a row and
consumed none, so repeated calls grew the table without limit and left every superseded
secret enrollable. Outstanding pending credentials are cleared first, as the WebAuthn
challenge service already does.

Also: `randomBuffer` was duplicated between `utils/totp.ts` and `services/totpService.ts`,
and both copies carried a fallback for `crypto.randomBytes` returning something other than a
Buffer, which it never does. The shared test double did return a bare object, so the
production fallback existed to satisfy an inaccurate mock; the double now returns a real
Buffer and the fallback is gone. `createOAuthState` returns the payload alongside the signed
value, so the caller no longer verifies a token it just signed to read back fields it had
just set.
