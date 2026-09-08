---
'seamless-auth-api': minor
---

Ship admin dashboard v0.5.0 in the API image.

`SEAMLESS_ADMIN_DASHBOARD_REF` moves from v0.4.0 to v0.5.0, so the SPA served at `/console` picks
up that release. The events table now names the acting administrator separately from the subject
of an administrative action, and the device-replacement recovery collects identity proofing (the
confirmation method, an evidence reference, and an approver for the remote exception) before it
prepares the replacement, matching what this API already records and requires.

The ref is a release tag rather than a floating branch, so the dashboard only changes when this
value does.
