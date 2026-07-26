---
'seamless-auth-api': minor
---

Auto-grant the admin role to a user who signs up with an `OWNER_EMAIL` address.
Managed instances are provisioned with `OWNER_EMAIL` (the tenant owner, optionally
a comma separated list); when that user first registers (email/OTP) or signs in
through a verified OAuth profile, they receive the `admin` role in addition to the
default roles, provided `admin` is an available role. This makes the bundled
`/console` admin dashboard usable on a freshly provisioned instance without a
separate bootstrap-promotion step. The grant is a no-op when `OWNER_EMAIL` is
unset, so non-managed deployments are unchanged, and it only ever applies to an
email whose control the signup flow has already verified.
