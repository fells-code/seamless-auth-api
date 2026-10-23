---
'seamless-auth-api': minor
---

`OAUTH_ALLOW_UNBOUND_STATE` is removed. Every OAuth callback must carry the binding `/start` returned, as clients from `@seamless-auth/client` 0.7.1 (`@seamless-auth/react` 0.18.1, `@seamless-auth/react-native` 0.3.3) do. A callback without one is refused with `400 Invalid OAuth state` and audited as `state_binding_missing`, whatever the variable says. A deployment that still sets it gets a boot warning that it is ignored.

Breaking for any client older than those SDK versions that starts OAuth sign-in: upgrade it before this release.
