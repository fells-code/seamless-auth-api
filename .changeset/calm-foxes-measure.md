---
'seamless-auth-api': minor
---

`GET /internal/metrics/funnel` reports how long the passwordless path takes and how far
passkeys are adopted.

Four blocks, each carrying the count it was computed over: `timeToRegistration` (self-serve
account creation to first completed sign-in, per user), `timeToLogin` (`login_success` to the
completed sign-in it led to, per attempt), `passkeyAdoption` (of the accounts created in the
window, how many hold a passkey) and `timeToFirstPasskey`. Medians and p90s are in seconds and
`null` when there is nothing to measure. The endpoint takes the same `from` and `to` window as
the other metrics routes and sits behind `admin:read`.

Passkey adoption is counted from `credentials` rows rather than events, because
`registration_success` fires on new-user registration, phone registration, magic link
completion and passkey enrollment alike. Time to login is bracketed by user and time, since the
ephemeral token carries no flow id: the first completed sign-in after a `login_success`,
within the five minute ephemeral TTL and before that user's next attempt. OAuth attempts are not
included, as `oauth_login_started` carries no user id.
