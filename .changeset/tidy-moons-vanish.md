---
'seamless-auth-api': minor
---

Drop `sessions.refreshTokenHash`.

The previous release stopped writing and reading the column and dropped its `NOT NULL`. This
one removes it, along with the field on the model.

Deliberately a separate release rather than a follow-up commit in the same one. An instance
still running the version that writes the column will insert a session during a rolling
deploy, and if the column is already gone that insert fails, which means every sign-in fails
for as long as both versions are running. The column has to stop being written in one release
and disappear in a later one, and this is the later one. Do not squash it back into the
release that stopped writing it.

Nothing reads the value, so there is nothing to migrate. The `down` restores the column as
nullable rather than `NOT NULL`, because the values are gone and there is no backfill that
would mean anything.
