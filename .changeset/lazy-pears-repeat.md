---
'seamless-auth-api': minor
---

Ask for exactly the user verification that will be enforced.

Registration advertised `userVerification: 'preferred'`, telling the
authenticator verification was optional, and then rejected a response that
skipped it, because SimpleWebAuthn's `requireUserVerification` defaults to true
and this server never set it. A user on an authenticator that skips verification
completed the whole ceremony and failed at the last step, having never been asked
to verify. Authentication separately asked for `required`, so the two halves
disagreed.

`authenticator_policy.userVerification` now drives both, for registration and
authentication, so what the browser is asked for and what the server accepts come
from one value and cannot drift. It accepts `required`, `preferred` or
`discouraged` and defaults to `required`.

The default does not change what is accepted, since that was already enforced. It
changes what is asked for, so an authenticator is told to verify rather than
being allowed to skip and be rejected afterwards.

Step-up deliberately still requires verification regardless of the policy. It
exists to re-verify the human, and without verification it is a second signature
from a key the session already proved it holds.

Requires `@seamless-auth/types` 0.13.0.
