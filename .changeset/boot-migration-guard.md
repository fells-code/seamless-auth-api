---
'seamless-auth-api': minor
---

Migrations can now run once per deploy instead of on every container start.

- The server checks at startup that every migration it ships with has been applied, and refuses to start while one is pending. This uses one query on the connection startup already opens. An older build starting against a newer schema, as a rollback does, is allowed and logged.
- `RUN_MIGRATIONS=false` skips the entrypoint's migration step, which on a 0.5 vCPU task was about 3 of the 6.8 seconds of boot. The default is unchanged.
- Running the image with the `migrate` argument validates the environment, applies pending migrations (creating the database if needed) and exits, for a one-off task per deploy. That also ends the race where every task in a scaled service applied the same migration.

A process started directly with `node dist/server.js` against an unmigrated database now exits with a message naming the first pending migration, instead of failing later on a missing column.
