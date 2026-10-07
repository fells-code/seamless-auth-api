---
'seamless-auth-api': minor
---

`GET /internal/metrics/dashboard` and `GET /internal/security/anomalies` accept `from` and `to` (#132), with the same validation as the `/internal/auth-events/*` endpoints and a default of the last 24 hours. Both responses carry the `window` they covered.

- Dashboard metrics adds `newUsers`, `loginSuccess`, `loginFailed`, `successRate`, `otpUsage` and `passkeyUsage` for the requested window. The `*24h` fields keep meaning the last 24 hours.
- Security anomalies takes `limit` (1 to 200, default 200) and `offset`. `total` now counts every match in the window. It used to report the number returned, which was capped at 200, so a caller could not tell there were more.

Requires `@seamless-auth/types` 0.28.0.
