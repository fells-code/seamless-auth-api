---
'seamless-auth-api': minor
---

`GET /oidc/payloads/DeviceCode/:id` now returns a device code for 10 minutes after it expires, with its `exp`, instead of 404, and the purge job keeps it that long (#542). The provider service hands that record to its library, which answers a client polling with an expired code `expired_token` (RFC 8628 section 3.5) rather than `invalid_grant`. A code that never existed, one past that window, the by-user-code lookup and every other model still answer 404 once expired, and an expired code can never be consumed.
