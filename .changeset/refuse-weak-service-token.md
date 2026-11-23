---
'seamless-auth-api': minor
---

With `NODE_ENV=production`, the server now refuses to start when `SEAMLESS_SERVICE_TOKEN` (or the fallback `API_SERVICE_TOKEN`) is shorter than 32 bytes or is a published default or placeholder value, such as `local-development-service-token-not-for-deployment` from `docker-compose.yml` or `GRAB_FROM_SEAMLESS_AUTH_PORTAL_DEV` from the templates (#599). The token is the key that signs service tokens, so a guessable value lets anyone call the API as a trusted adapter. `validateEnvs.sh` applies the same check before migrations run, and `src/config/serviceToken.ts` applies it at boot.

This is a breaking change for a production deployment that kept one of those values. Before upgrading, set a new token with `openssl rand -base64 48` on the API and on every server adapter that calls it. Development and test runs are unchanged.
