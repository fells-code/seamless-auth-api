---
'seamless-auth-api': patch
---

The bundled admin console at `/console` moves to dashboard v0.10.1, which sends the OAuth state binding. Since 0.19.2 the API refuses an OAuth callback without it, so signing in to the console with an OAuth provider failed on 0.19.2 unless `OAUTH_ALLOW_UNBOUND_STATE=true` was set.
