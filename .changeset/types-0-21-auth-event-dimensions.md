---
'seamless-auth-api': patch
---

Return the telemetry dimensions from `GET /admin/auth-events`.

`@seamless-auth/types` moves from `^0.20.0` to `^0.21.0`. The listing validates its response
against the shared `AuthEventSchema`, which strips what it does not declare, so until 0.21.0
carried `deployment_id`, `device_class`, `mail_provider`, `owner` and `attempt_id` the columns
were written on every row and never returned. They are now, and `openapi.json` documents them.
