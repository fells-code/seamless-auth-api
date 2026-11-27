---
'seamless-auth-api': minor
---

Organization role grants are stricter. Except for an instance `admin:write`, nobody can add a role to their own membership, and a role granted to someone else can only carry permissions the manager holds, and custom claims only if the manager holds that role. Owners are no longer exempt. `PATCH /organizations/:organizationId/members/:userId` answers `403` naming the refused roles, as before.

Any signed-in user can create an organization and becomes its `owner` and `admin`, so permissions and custom claims mapped onto those built-in roles are available to every user. Move anything that should be granted deliberately to another role. To review grants made before this release, look for `organization_member_updated` audit events whose actor is also the member and whose `rolesAdded` is not empty.
