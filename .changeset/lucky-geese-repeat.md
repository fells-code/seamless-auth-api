---
'seamless-auth-api': minor
---

Broaden the internal metrics endpoints beyond login success and failure.

Auth event types are now rolled up into mutually exclusive categories (`suspicious`, `login`,
`registration`, `webauthn`, `oauth`, `magicLink`, `otp`, `totp`, `stepUp`, `token`, `system`,
`other`). Previously the grouping matched on substrings in order, so `webauthn_login_success` and
`oauth_login_success` were counted as plain logins and never appeared in their own buckets.

- `/internal/auth-events/timeseries` buckets now carry `total` and a `categories` map.
  `success` and `failed` stay login-only, so existing dashboards keep working.
- `/internal/auth-events/grouped` returns the new categories in `summary` plus an `outcomes`
  roll-up, counts in the database instead of loading every auth event into memory, and accepts
  `from`, `to`, and `userId`.
- `/internal/auth-events/login-stats` and `/internal/auth-events/summary` accept the same
  `from`, `to`, and `userId` filters as the other metrics endpoints.

Two date-window fixes: the timeseries used to validate `from`/`to` and then return a now-relative
window anyway (and with `interval=day` it queried only the last 24 hours while filling 30 daily
buckets). Buckets now span the requested window. The maximum window is also capped per interval,
31 days for `hour` and 366 days for `day`, and an open-ended window is measured against the
current time rather than being unbounded.
