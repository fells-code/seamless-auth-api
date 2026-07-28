---
'seamless-auth-api': minor
---

Make scoped admin roles assignable and discoverable.

`POST /admin/users` and `PATCH /admin/users/:userId` now reject any role that is not in
`available_roles` with `400 Invalid roles`, naming the offending roles in `details.roles`.
Previously a typo like `admin:reed` was accepted and stored, granted nothing because enforcement
never matches an unlisted role, and reported no error. The match is exact, so wildcards and deeper
scopes must be listed to be handed out. An empty or unreadable role catalog skips the check rather
than rejecting every assignment.

`PATCH /admin/users/:userId` previously returned its `400` through a schema that stripped
`details`, so the caller could not see what was rejected. Both user endpoints now use a validation
error schema that carries it, and `POST /admin/users` declares its `400` and `409` responses in
OpenAPI.

The `OWNER_EMAIL` grant is now `admin:write` rather than a bare `admin`, stating the owner's
authority in the scoped vocabulary. Instances whose `available_roles` lists only `admin` still get
`admin`, which is equivalent in power, so the grant never becomes a no-op.

`.env.example` now ships `admin:read` and `admin:write` in `AVAILABLE_ROLES` so the console's role
picker offers read-only admin. `AVAILABLE_ROLES` seeds `available_roles` on first boot only, so
existing instances need the scoped roles added through the admin system-config endpoints.
