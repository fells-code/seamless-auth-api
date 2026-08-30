---
'seamless-auth-api': minor
---

Stop the login request body downgrading a passkey-only policy.

`POST /login` accepts a `passkeyAvailable` hint so a client without WebAuthn
support is offered something it can actually complete. That hint was folded into
the decision about whether passkey was usable at all, and the passkey-only branch
was gated on the result. So a caller sending `passkeyAvailable: false` skipped
that branch and was offered `magic_link`, `email_otp` and `phone_otp` instead,
which turned off `passkey_login_fallback_enabled: false` from the request body.
The one setting whose job is to keep a passkey-holding account on passkeys could
be switched off by the account's own client.

The hint is now advisory, which is all a self-reported capability can safely be.
It can remove passkey from a set the policy already permits, and it cannot add a
weaker method to a passkey-only one.

**Behaviour change.** With `passkey_login_fallback_enabled: false`, an account
that holds a passkey is now offered passkey only, whatever the client reports. A
browser that genuinely cannot run the ceremony cannot sign in to such an account,
which is what passkey-only means: the previous behaviour offered email OTP to
anyone who claimed not to support passkeys. Accounts with no passkey are
unaffected and keep the configured methods.

This also closes a quieter version of the same problem. The React SDK computes
the hint asynchronously and starts from `false`, so a user submitting before that
check resolves, or hitting the error path, sent `passkeyAvailable: false` from a
perfectly capable browser and was silently dropped to a weaker method.
