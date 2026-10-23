---
'seamless-auth-api': patch
---

Log out everywhere can no longer miss a session a concurrent refresh was creating (#471).

- `DELETE /logout/all`, `DELETE /sessions`, `DELETE /admin/sessions/:userId/revoke-all`, device-replacement recovery and OAuth provider retirement revoke with one bulk update instead of reading the sessions and revoking them one at a time.
- Each also records a per-user cutoff. A session created at or before it is refused on every authenticated request and on `POST /refresh`, which re-reads the cutoff after claiming the rotation, so a rotation that started before the revoke cannot produce a live session. The refusal is `401 invalid_refresh_token`, with `refusal: 'sessions_revoked'` on the `refresh_token_failed` auth event.
- Validating an access token now reads the cutoff from the session owner's row, one indexed lookup per authenticated request.
- Migration: `users` gains `sessions_revoked_before`.
