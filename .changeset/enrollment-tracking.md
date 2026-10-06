---
'seamless-auth-api': minor
---

Track and invite passkey enrollment, for moving an organization onto passkeys after importing its users (#338).

- `GET /admin/enrollment` lists active users with their WebAuthn credential count and status (`none`, `one`, `two_or_more`), filterable by organization, status, imported users and email, with a per-status summary.
- `POST /admin/enrollment/invites` emails users a notice to sign in and add a passkey. The link is the tenant's sign-in page (`signInUrl`, default `<frontend_url>/login`) and carries no credential.
  - Targets are `userIds` (up to 200) or an `organizationId`, whose unenrolled members are invited 200 at a time. Anyone invited in the last day is skipped, and the response reports what `remaining` is left.
  - With `x-seamless-auth-delivery-mode: external`, each result carries the delivery for the caller to send.
  - Answers 409 when no sign-in method other than passkey is enabled.
  - Each invite is logged as `admin_enrollment_invite_sent`.
- New `prompt_passkey_enrollment` setting (default `false`, env `PROMPT_PASSKEY_ENROLLMENT`). With it on, email and phone code sign-ins and magic link sign-ins carry `nextStep: 'enroll_passkey'` for a user with no passkey.

Requires a database migration, `@seamless-auth/types` with the enrollment schemas, and `@seamless-auth/messaging` with `sendEnrollmentInviteEmail`.
