---
'seamless-auth-api': minor
---

Give `POST /login` a single rejection shape and record the server's security posture.

Every `/login` failure now answers an identical `401 { "error": "Not Allowed" }`. An unknown
identifier, an unverified account, an account with no permitted continuation method, and a failure
to mint the pre-auth token previously produced three distinguishable bodies, so an unauthenticated
caller could tell which case it had hit. The reason is still recorded in the `login_failed` auth
event metadata, so operators keep the detail.

The two identifier-lookup failure branches, which fire when the database is unreachable rather
than when the identifier is unknown, answered `401` on the email path and `403` on the phone path.
Both now answer `500 { "error": "Server error" }`, so an outage is reported as an outage instead
of as a failed login.

`loginMethods` is unchanged on the success response. Removing it buys no enumeration benefit until
unknown identifiers also receive a decoy token, and dropping it early would degrade legitimate
clients to a default method list.

New `docs/security-posture.md` states the deliberate tradeoffs and their mitigating controls: the
residual enumeration on `/login` and what closing it would take, ephemeral token replay within its
5 minute TTL, email and phone being plaintext at rest, and the per-deployment `aud` scheme.
