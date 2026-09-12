---
'seamless-auth-api': minor
---

Ship admin dashboard v0.7.0 in the API image.

`SEAMLESS_ADMIN_DASHBOARD_REF` moves from v0.6.0 to v0.7.0, so the SPA served at `/console`
picks up that release. Overview gains a Passwordless Funnel section (time to registration, time
to login, passkey adoption and time to first passkey, each with the count behind it) and a
Sign-in Outcomes section (success rate, where attempts stop, and the breakdown by method,
device and mail provider).

Both read routes that ship in the same API release as this change, `GET /internal/metrics/funnel`
and `GET /internal/metrics/sign-ins`, so the image and the console it serves agree. The ref is a
release tag rather than a floating branch, so the dashboard only changes when this value does.
