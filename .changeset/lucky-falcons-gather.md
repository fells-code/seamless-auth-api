---
'seamless-auth-api': minor
---

Update `@seamless-auth/types` to 0.19.0 and adopt what it adds.

Two schema changes come in with the bump, which spans 0.17.0 to 0.19.0.

**`authenticator_policy.syncedPasskeys` now defaults to `allow` in the shared schema.**
This API already made that change for itself in 0.8.0, defaults and migration included, so
nothing about how an instance behaves moves here. What changes is the published contract:
`openapi.json` and the generated types stated `block` while the server did `allow`, and they
now agree.

**`magic_link_redirect_uris` is honoured rather than accepted and ignored.** The key arrived
in 0.17.0 of the shared schema, which means the admin system-config API started accepting it
the moment this bump landed, since the patch schema refuses unknown fields. Nothing read it.
An operator could set a magic link redirect allowlist, receive a success, and still have
every destination validated against `origins`. A redirect control that reports success and
does nothing is worse than one that is absent, so `resolveMagicLinkUrl` now matches against
it.

Entries are matched exactly, which is the point of the key: it exists for destinations whose
origin cannot be compared, such as a custom application scheme like `myapp://auth` or a
universal link on a host that should not also be a WebAuthn origin. The list is empty by
default and an empty list falls back to comparing against `origins`, so a deployment that
sets nothing sees no change. A deployment that does set it is opting into an exact allowlist
and its `origins` no longer apply to magic links.

`openapi.json` and `src/generated/api.ts` are regenerated. The committed document also still
carried `info.version` `0.7.4`, which regeneration corrects to the released version; the
contract test ignores `info`, so it had gone unnoticed.
