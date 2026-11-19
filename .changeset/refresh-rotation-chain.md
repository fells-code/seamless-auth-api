---
'seamless-auth-api': minor
---

Refresh rotation fixes:

- `DELETE /sessions/:id` and `DELETE /admin/sessions/by-id/:id` revoke the whole chain from the row given, so a session that rotated after it was listed is revoked at its head instead of surviving while the API answers 200 (#592).
- A rotated refresh token is treated as reuse however long after its rotation it is presented. It used to be answered `401 invalid_refresh_token` once the rotated row's idle window had passed, without revoking the chain. It is now `401 refresh_token_reused` and the chain is revoked (#593).
- New refresh replay window (#598): for `REFRESH_REPLAY_WINDOW_SECONDS` (default 10, at most 60, `0` disables) after a rotation, the rotated token is answered with the same successor, up to three times, so two adapter instances refreshing at once no longer sign the user out. The response shape is unchanged. Only the immediate predecessor of a live head qualifies. The successor token is stored encrypted on the rotated row and cleared when the window lapses or the chain is revoked.

Adds a migration for the `rotatedAt`, `replayTokenCiphertext` and `replayCount` session columns.
