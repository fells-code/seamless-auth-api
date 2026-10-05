---
'seamless-auth-api': minor
---

Add `POST /admin/users/import` for moving users across from another identity system. It takes up to 200 rows per request, matches each on the source system's id and then on email, and applies each row on its own so one rejected row does not stop the batch. `dryRun` reports the outcome without writing.

Imports carry no credentials: an imported user stays unverified until they register with the imported email. Roles and organization memberships are only ever added, an existing account's email is never changed, admin roles are refused, and an external id is never linked to an existing account that holds an admin role. Each created or updated account is recorded as `admin_user_imported` and each batch as `admin_user_import_completed`, against the acting admin.

Adds the `user_external_ids` table (migration `20261005120000`). Requires `@seamless-auth/types` 0.23.0.
