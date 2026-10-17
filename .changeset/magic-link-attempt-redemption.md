---
'seamless-auth-api': patch
---

Magic link sign-in issues one session per confirmed link, to the attempt that requested it (GHSA-9jg2-jjqq-3346).

- Each link records the `jti` of the ephemeral token that requested it, and `GET /magic-link/check` only looks up links for the polling attempt. Another ephemeral token for the same address cannot collect it.
- The first check after the link is confirmed issues the session and marks the link redeemed. Later checks for the same attempt answer `200 { "message": "Success" }` without tokens, so a second tab in the same browser still sees the sign-in complete and reads the session it already has.
- A request or poll with an ephemeral token that has no `jti` is refused with `400`.
- Migration: `magic_link_tokens` gains `attempt_id` and `redeemed_at`. Links requested before the upgrade can no longer be collected; they expire within fifteen minutes.
