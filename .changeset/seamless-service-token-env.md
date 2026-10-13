---
'seamless-auth-api': minor
---

Read the service token from `SEAMLESS_SERVICE_TOKEN`, the name used across the Seamless ecosystem.

- `SEAMLESS_SERVICE_TOKEN` is now the preferred env var for the trusted server-adapter and internal bearer secret, and for the secrets that fall back to it (`REFRESH_TOKEN_LOOKUP_SECRET`, `TOTP_SECRET_ENCRYPTION_KEY`, `OAUTH_STATE_SECRET`, `DECOY_SUBJECT_SECRET`).
- `API_SERVICE_TOKEN` keeps working as a fallback, so existing deployments need no change. When only the old name is set, the server logs one info notice at boot naming the preferred variable.
- Setting both names to different values stops the server at boot with an error naming both. Setting both to the same value is fine.
- `validateEnvs.sh` accepts either name, and the bundled compose files now pass `SEAMLESS_SERVICE_TOKEN` (falling back to `API_SERVICE_TOKEN` from the host environment).
