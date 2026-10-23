---
'seamless-auth-api': patch
---

The bundled Docker Compose stack serves on loopback only and no longer grants admin to a fixed address (#473).

- `docker-compose.yml` publishes the API on `127.0.0.1:${API_PORT:-5312}` and no longer publishes Postgres. Docker's port publishing bypasses host firewalls such as ufw, so the old bare port exposed the development defaults to the network. `POSTGRES_PORT` no longer applies to this file; use `docker compose exec postgres psql -U seamless seamless_auth` for a shell.
- `docker-compose.dev.yml` publishes the API and Postgres on `127.0.0.1` only.
- Neither file defaults `OWNER_EMAIL` to `owner@example.com` any more. Pass your own, for example `OWNER_EMAIL=you@example.com docker compose up`; without it nobody is granted admin. An existing stack whose owner account was already created keeps its role.

The release image now builds the admin dashboard from a pinned commit (`SEAMLESS_ADMIN_DASHBOARD_REF`, dashboard v0.10.1) and refuses a build arg that is not a full commit SHA (#474). Overriding it with a tag or branch name fails the build.
