---
'seamless-auth-api': minor
---

Let a magic link request choose where the link lands.

The link was always built from one tenant-wide value, `frontend_url` falling back to
the first configured origin. A tenant with both a web app and a mobile app could not
serve both, because a link has to arrive in one or the other.

`GET /magic-link` now takes an optional `redirectUri` query parameter. A supplied value
is validated against the configured `origins`, exactly the way `resolveOAuthRedirectUri`
already validates an OAuth redirect, and a value outside them answers `400`. The token is
set as a `token` query parameter on the target, replacing one of that name the caller had
already put there so the client is never handed two.

**Additive.** Omit the parameter and the destination is unchanged, so no existing caller
has to do anything.

The redirect matching that OAuth had inline is now `src/lib/redirectAllowlist.ts` and
shared by both flows, so an auth server has one place where "may we send someone here"
is decided rather than one per flow.

The allowlist is the WebAuthn `origins` list because there is no dedicated one. A
destination that cannot be expressed as one of those, a custom scheme like `myapp://` or
a universal link on a host that is not a WebAuthn origin, needs a
`magic_link_redirect_uris` system config key. That key would live in
`@seamless-auth/types` and needs a coordinated release, so it is deliberately left as a
follow-up rather than bundled here.
