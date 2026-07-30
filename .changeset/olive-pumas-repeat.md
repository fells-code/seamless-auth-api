---
'seamless-auth-api': minor
---

Ship admin dashboard v0.4.0 in the API image.

`SEAMLESS_ADMIN_DASHBOARD_REF` moves from v0.3.0 to v0.4.0, so the SPA served at `/console` picks
up that release. It brings keyboard and screen-reader operability across the app shell and charts,
a step-up path for admins with no passkey, editable organization memberships, inline validation and
unsaved-changes warnings in system configuration, refresh and export on monitoring, and fixes to
the user directory, the events view, and sign-in failure messaging.

The ref is a release tag rather than a floating branch, so the dashboard only changes when this
value does.
