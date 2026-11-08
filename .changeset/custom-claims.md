---
'seamless-auth-api': minor
---

Add static custom claims (ADR 0005, #417).

- Admin API under `/admin/custom-claims`: list every source with the reserved names, prefixes and budget, and read, replace or delete the set for an instance role, an organization role or an OpenID Provider client. Writes take step-up and are audited by claim name, never value.
- A set is refused when it uses a reserved name or prefix, a name outside `^[a-z][a-z0-9_]{0,63}$`, a value nested deeper than 3, or more than 1 KiB. The role or client must exist.
- First-party access tokens now carry the claims of the user's instance roles, then of their roles in the active organization (only while the membership exists), then the session's `pre_token` hook claims, a later source winning per name. Roles of one kind apply in name order. Recovery tokens carry none.
- OpenID Provider client sets are stored and served here, and applied by the provider in a later release.
- When the sources together exceed 1 KiB, the token carries no custom claims and the mint writes `custom_claims_omitted`. Nothing is trimmed.
- Retiring an instance role, deleting an organization role, or deleting an OpenID Provider application deletes its custom claims, so adding the name back does not restore them.
- New audit events `admin_custom_claims_updated`, `admin_custom_claims_deleted` and `custom_claims_omitted`.
