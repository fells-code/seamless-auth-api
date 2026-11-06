# ADR 0004: Permissions and organization roles in the access token

- **Status:** Accepted
- **Date:** 2026-11-05
- **Issues:** #415, #416, seamless-auth-types#98. Guards follow in seamless-auth-server#218, seamless-auth-go#29, seamless-auth-python#32 and seamless-auth-rust#33.

## Context

Two role systems exist and neither carries permissions.

- **Instance roles** are `users.roles`, validated against `available_roles`. They reach the token as `roles` and match through `roleGrantsAccess`, which is colon-scoped and implies some grants.
- **Organization roles** are `organization_memberships.roles`, free-form strings with `owner`, `admin` and `member` by convention. Only `org_id` reaches the token, so a backend cannot authorize per organization without asking the API. Membership `scopes` gate the API's own organization routes.

Every adopter ends up writing a role-to-capability table of its own.

## Decisions

### P1. One catalogue, one mapping

`permissions` holds the catalogue. `role_permissions` maps a role, named by kind (`instance` or `organization`) and name, to a permission.

- `available_roles` stays the instance role registry. Moving it would change the system config contract, the CLI and the console, for no gain here. Removing a role from it deletes its mappings, so adding the name back later cannot silently restore old grants.
- A role's permissions come from the literal name held. Holding `billing` does not pick up a mapping on `billing:read`, so the console can show exactly why someone has a permission.
- Deleting a permission a role still grants is a 409. Taking access away is a decision about the role.

### P2. Claims are flat, and organization claims stay apart

```json
{
  "sub": "user uuid",
  "sid": "session uuid",
  "typ": "access",
  "roles": ["user"],
  "permissions": ["reports:read"],
  "org_id": "org uuid",
  "org_roles": ["admin"],
  "org_permissions": ["projects:write"]
}
```

- `roles` and `org_id` do not change. Verify-only parsers in every adapter refuse a token whose `roles` is not a string array, so that shape is frozen.
- Organization roles never merge into `roles`. A guard on `requireRole('admin')` must not pass for an organization admin.
- With no active organization, all three `org_*` claims are absent.
- Flat rather than a nested `org` object, so `org_id` stays where adapters already read it and Go and Rust need no nested type.

### P3. Permissions match exactly

`invoices:read` matches only `invoices:read`, with no wildcards and no implied grants. Any JWT library can check the token with a plain membership test, nothing is granted that the console does not list, and there is less to keep identical in four languages. Names use the role alphabet, which has no `*`.

This differs from `requireRole`, deliberately. Roles keep their scoped matching.

### P4. A set that does not fit is omitted whole

The organization roles and the two permission arrays get 1 KiB, serialized, together. A server adapter keeps the whole access token inside a signed cookie, so it is base64 encoded twice under the browser's 4 KiB cookie limit, and a test builds that cookie at the budget. Over the budget all three are replaced with `"permissions_omitted": true`.

Nothing is trimmed, because a partial list looks complete and denies silently. A guard that sees the marker reads `GET /users/me/permissions` with the caller's token and fails closed if it cannot. A plain 403 would turn an organization growing past a limit into an outage.

### P5. Organization roles are a catalogue

`organization_roles` is instance-wide, seeded with the built-in `owner`, `admin` and `member` and every distinct value already in memberships. The migration rewrites no membership, including legacy values a new role name could not use, so nobody loses a role. Assigning a role outside the catalogue is a 400. Built-ins cannot be deleted, because the API's own organization routes depend on them, and a role still held cannot be deleted.

Per-organization custom roles belong to v1.1 and can be added with a nullable column.

### P6. What a guard checks

`requirePermission` passes on `permissions` or `org_permissions`, so an instance-wide grant applies everywhere. An option restricts it to the active organization and can bind a route's organization id to `org_id`. Without that binding, a token for organization A passes on `/orgs/B/...`, so the guide leads with the bound form. Adapters ship this in their own issues; the semantics are settled here.

### P7. Who can grant organization roles

Role changes need step-up and are audited. Only an owner or an instance `admin:write` can grant or remove `owner`. A manager can only grant a role whose permissions they hold. Without this an organization admin could make themselves owner, or hand out any permission-bearing role, with no record.

### P8. One place mints a token

Sign-in, refresh, organization switch and session exchange all call `mintAccessToken`, so they cannot disagree about what a token grants. It reads the membership each time. With no membership, the organization claims are dropped and the session's organization is cleared, so removal from an organization reaches the token at the next refresh. Recovery tokens carry no permissions and no organization claims.

## Consequences

- **Staleness.** Permissions are as fresh as the access token TTL, the same as `roles`. `GET /users/me/permissions` is live for a check that cannot wait.
- **Membership `scopes` stay out of the token.** They gate Seamless's own organization routes and are not app permissions.
- **Assigning an unlisted organization role is now a 400**, which is a behavior change for callers that invented role names at runtime.
- **Provider tokens are not covered.** `/oidc/sign` refuses unlisted claims, the provider's claims map replaces library defaults, `OidcAccountClaimsSchema` strips unknown keys, and its `org_id` is the default organization rather than the session's active one. seamless-auth-oidc-provider#47 takes that up and reuses these claim names.
