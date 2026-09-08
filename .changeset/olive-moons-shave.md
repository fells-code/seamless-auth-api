---
'seamless-auth-api': minor
---

Ship admin dashboard v0.6.0 in the API image.

`SEAMLESS_ADMIN_DASHBOARD_REF` moves from v0.5.0 to v0.6.0, so the SPA served at `/console` picks
up that release. Organizations pages and searches on the server and gains a remove action,
Overview and Security take a date range, and System Configuration grows an Authenticator Policy
section covering all seven fields.

Each of those needs API support that is already in place here: `DELETE
/admin/organizations/:organizationId` exists, the organization list accepts `limit`, `offset` and
`search`, the internal metrics endpoints take `from` and `to`, and `authenticator_policy` is a
system config key.

The ref is a release tag rather than a floating branch, so the dashboard only changes when this
value does.
