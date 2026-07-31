---
'seamless-auth-api': patch
---

Send the registration response's `ttl` as a number.

It was the string `'300'`, the only `ttl` this API sends that was not a number. A caller sets its
registration cookie from it, and the Fastify adapter passes the value to a cookie library that
requires an integer, so registration failed there with `TypeError: option maxAge is invalid: 300`.
The Express adapter multiplies it into milliseconds, which coerces the string, so the same response
worked and the mismatch went unnoticed.

Requires `@seamless-auth/types` 0.6.0, where `RegistrationSuccessSchema.ttl` becomes a number.
Response bodies are validated against that schema at runtime, so the two move together.
