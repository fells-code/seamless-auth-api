---
'seamless-auth-api': patch
---

Adding someone to an organization requires an administrator (GHSA-v2q2-q246-8chm).

- `POST /organizations/{organizationId}/members` now requires `admin:write`, the same as `POST /admin/organizations/{organizationId}/members`, and answers `403` otherwise. Any account could create an organization and then add other accounts by email without their consent, which also told it which addresses have accounts. Self-service adds return in v0.20 as invitations the member accepts.
- `GET /organizations/{organizationId}/members` and the member returned by `PATCH /organizations/{organizationId}/members/{userId}` show the member's `phone` and global `roles` only to `admin:read` callers. Others get `phone: null` and `roles: []`; organization roles and scopes are unchanged.

Breaking for apps that let non-administrators call `addOrganizationMember` from `@seamless-auth/client`: those calls now fail with `403`. The admin dashboard and the CLI use the admin routes and are unaffected.

Earlier versions did not record who added a member. If self-service organizations were in use, review `organization_memberships` for members of organizations that a non-administrator created.
