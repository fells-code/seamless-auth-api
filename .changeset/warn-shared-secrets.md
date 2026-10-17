---
'seamless-auth-api': patch
---

The server logs a warning at boot naming each of `REFRESH_TOKEN_LOOKUP_SECRET`, `TOTP_SECRET_ENCRYPTION_KEY`, `OAUTH_STATE_SECRET` and `DECOY_SUBJECT_SECRET` that is unset and so falls back to the service token, with what rotating the service token would then break. `docs/production-operations.md` describes how to separate them safely: set each to the current service token value first, then rotate the service token.

The fallback to the service token is deprecated and is removed in v0.20, which requires each secret whose feature is in use. Set them now, to the current service token value, so the upgrade is a no-op.
