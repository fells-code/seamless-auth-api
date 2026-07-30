---
'seamless-auth-api': minor
---

Serve the publicly visible system configuration from an unauthenticated `GET /system-config/public`.

It returns the configured `loginMethods` and nothing else. The bundled sign-in screens in the SDKs
render before anyone has a session, so they cannot read the configuration and today fall back to a
hardcoded list of methods. That list can advertise a method an instance has turned off. This lets a
client ask instead.

It also unblocks offering a skip on passkey registration, which is only safe when another login
method is enabled. A client that cannot see the method list cannot make that call safely.

The handler reads through `getLoginPolicy`, so a tainted or partially written config answers with
the defaults rather than failing. A signed-out client with no methods has nothing to render, and a
500 here would take the sign-in screen down with it.

Every other key in the system configuration stays behind the admin routes.
