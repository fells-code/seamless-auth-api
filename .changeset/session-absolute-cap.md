---
'seamless-auth-api': minor
---

Refresh rotation no longer resets the absolute session lifetime. Each session now records when its rotation chain began (`chainStartedAt`, new migration), and a rotated session expires at that start plus `refresh_token_ttl` instead of a full lifetime from the refresh. A session that refreshes continuously therefore ends at the absolute bound and the user signs in again. The idle bound still slides on each refresh, capped at the absolute one.

`refreshTtl` in the `/refresh` response is now the time left in the chain rather than the full `refresh_token_ttl`. A refresh refused because the chain ran out, or because the session went idle, is recorded as `refresh_token_failed` with `metadata.refusal` set to `absolute_lifetime_reached` or `idle_timeout`, so it can be told apart from an unknown or revoked token. Sessions that exist when the migration runs are capped from their most recent refresh.
