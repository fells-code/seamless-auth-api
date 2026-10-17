---
'seamless-auth-api': minor
---

The API refuses to leave a deployment with nobody who can administer it.

`DELETE /admin/users`, a role change through `PATCH /admin/users/{userId}`, and `DELETE /users/delete` now answer `409 { "error": "last_admin" }` when they would remove the last active user holding `admin:write` (granted by `admin`, `admin:write` or `admin:*`). The refusal is audited as `admin_last_admin_change_refused`. Previously the only way back was a direct database edit, since `OWNER_EMAIL` grants admin only when the account is created.
