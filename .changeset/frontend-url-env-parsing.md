---
'seamless-auth-api': patch
---

Parse the `FRONTEND_URL` env var as a single string in `parseSystemConfigEnvValue`.
The `frontend_url` system config was added to the env map and schema but never
handled by the env parser, so bootstrap threw `Unhandled system config key:
frontend_url` whenever `FRONTEND_URL` was set. Document the variable in
`.env.example`.
