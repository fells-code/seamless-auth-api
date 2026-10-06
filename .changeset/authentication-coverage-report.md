---
'seamless-auth-api': minor
---

Add an authentication coverage report for assessment and insurance responses (#178).

- `GET /admin/reports/authentication-coverage` (admin read) reports, for a period (`from`, `to`, default the last 90 days), how many active users hold a passkey overall, per organization and per `month` or `week` bucket, alongside the login and authenticator policy enforced now, the authenticator mix by AAGUID (with backup eligibility) and completed sign-ins by method.
- `organizationId` scopes every figure to one organization's current members.
- `format=csv` returns the same report as a `text/csv` attachment for pasting into a document.
- Code sign-ins now record `metadata.channel` (`email` or `sms`) on `verify_otp_success`, so the report can tell email codes from phone codes. Older rows are reported as `otp`.
