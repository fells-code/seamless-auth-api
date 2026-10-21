---
'seamless-auth-api': patch
---

Bind the OAuth `state` to the client that started the sign-in (#463). The state was signed, expiring and single use, but anyone holding an unconsumed state and its provider code could finish the sign-in in another browser and sign that browser in to their own account (login CSRF, RFC 9700 section 4.7).

`POST /oauth/:providerId/start` now also returns a random `binding`, and its SHA-256 is signed into the state. `POST /oauth/:providerId/callback` must send that `binding` back, and a callback with a missing or different one is refused with 400 `Invalid OAuth state` before the provider is contacted. The `oauth_login_failed` auth event records `state_binding_missing` or `state_binding_mismatch`.

This breaks OAuth sign-in for clients that predate the binding. Upgrade `@seamless-auth/client`, `@seamless-auth/react` or `@seamless-auth/react-native`, which keep and send it; server adapters pass it through unchanged. A direct API integration must store `binding` from `/start` and send it with the callback. Until every client is upgraded, `OAUTH_ALLOW_UNBOUND_STATE=true` accepts a callback without one. It reopens the login CSRF while set, warns at boot, and is removed in v0.20.
