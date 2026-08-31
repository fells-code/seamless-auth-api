---
'seamless-auth-api': patch
---

Drop the vestigial `users.challenge` and `users.challengeContext` columns.

WebAuthn challenges moved to the `webauthn_challenges` table, which gave them a
purpose, an expiry and one-time use. These two were left behind so that release
could be rolled back without losing challenge state, and nothing has read or
written either since. Left in place they read as live state to anyone opening
`src/models/users.ts`.

The `down` restores both nullable, which is the shape they had. It does not
restore data and does not need to: a challenge lives 300 seconds, so anything a
rollback could carry across has already expired, and the worst case is an
in-flight ceremony that the user starts again.
