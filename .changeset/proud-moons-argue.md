---
'seamless-auth-api': minor
---

Add organization deletion and a paginated, searchable admin organization list.

The admin organization routes were less capable than the collections beside them, and the
gap blocked the admin dashboard. `GET /admin/organizations` accepted no query parameters
and returned every row, so a caller could not request a window or ask the server to
filter, and there was no way to delete an organization at all: the only `DELETE` in the
group removed a member.

**`DELETE /admin/organizations/{organizationId}`.** Deletes the organization and every
membership in it, in one transaction. Members themselves are untouched, and sessions
scoped to the organization stay active with no organization, though an access token
already issued carries the old organization id until it expires. Refusing to delete while
members remain was considered and rejected: every organization is created with an owner
membership, and member removal refuses to drop the last owner, so no organization created
through the API could ever reach zero members and such a route could never succeed.

**`limit`, `offset` and `search` on `GET /admin/organizations`.** The window matches the
shape `/admin/sessions` already uses, defaulting to 50 rows from offset 0 and capped at 100. `search` matches case-insensitively against name and slug, following
`GET /admin/users`. The response shape is unchanged, and `total` now counts every
organization matching the search rather than the length of the returned page, so a caller
can tell there is another page to ask for.

Both are additive. Callers that send no query parameters keep working, though a
deployment with more than 50 organizations will now receive the first 50 rather than all
of them, which is what `total` is for.
