---
'seamless-auth-api': minor
---

Add a one-command local stack. `docker compose up` now brings up Postgres and the published API
image together with development defaults, so trying the project no longer means setting up
Postgres, writing a `.env`, and generating secrets by hand. Migrations run on first boot, a
development signing keypair is generated, and the admin console is served at
`http://localhost:5312/console`. `OWNER_EMAIL` defaults to `owner@example.com`, so signing up with
that address gives a working admin.

The previous source-built stack moved to `docker-compose.dev.yml` for contributors. It no longer
requires a `.env` file (one is used when present, and its values win) and it no longer depends on
a prior `npm run build`, which meant it could not start from a fresh clone. A new `dev:container`
script runs the watcher without `--env-file`.

Neither compose file pins `container_name` any more, so a leftover container from an older stack
no longer blocks startup.
