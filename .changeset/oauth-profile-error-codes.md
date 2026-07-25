---
'seamless-auth-api': minor
---

Surface actionable OAuth callback failure codes.

The OAuth callback previously collapsed every profile failure into a generic
`400 { error: 'OAuth login failed' }`, so a user whose provider returned no email
(the most common case, for example a GitHub account with no public email) had no
way to know what to fix. The callback now returns a stable machine-readable `code`
alongside the existing `error` string for the curated, user-actionable cases:
`oauth_missing_email`, `oauth_email_not_verified`, and `oauth_missing_subject`.
Unexpected internal failures still return the generic message with no detail, and
the audit event records the specific reason instead of the blanket
`callback_failed` for the known cases.
