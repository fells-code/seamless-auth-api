---
'seamless-auth-api': patch
---

The bundled admin console at `/console` moves to dashboard v0.10.0. Its magic link page handles the confirmation step for a sign-in link opened on another device (new in 0.19.0), and it no longer requests `/config.js`, which 404'd on every load.
