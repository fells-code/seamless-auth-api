---
'seamless-auth-api': minor
---

The server's own secrets no longer fall back to the service token (#447).

- In production, `REFRESH_TOKEN_LOOKUP_SECRET` and `DECOY_SUBJECT_SECRET` are always required, `TOTP_SECRET_ENCRYPTION_KEY` once any TOTP credential exists, and `OAUTH_STATE_SECRET` once an OAuth provider is configured. The server refuses to start without the ones it needs and names each one.
- Adding an OAuth provider (`POST /system-config/oauth-providers`, or `oauth_providers` in `PATCH /system-config/admin`) answers `409 { "error": "secret_required", "variable": "OAUTH_STATE_SECRET" }` while it is unset, and `POST /totp/enroll/start` answers the same for `TOTP_SECRET_ENCRYPTION_KEY`.
- Development keeps a fixed development-only value for each unset secret, with a warning.
- The boot warning about secrets sharing the service token is gone, since none do.

Breaking for a production deployment that relied on the fallback: before upgrading, set each missing variable to the current service token value, so existing sessions, TOTP enrollments and OAuth sign-ins in flight stay valid. See docs/production-operations.md.
