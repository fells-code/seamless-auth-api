---
'seamless-auth-api': minor
---

Tokens are checked more strictly.

- Access and ephemeral tokens must carry `aud` equal to the issuer, as every token this server signs already does, and a `typ` of `access` or `ephemeral`. Previously the audience was not checked, so the posture doc's claim that it was held only for the adapters.
- Internal service tokens must carry an `exp` no more than an hour (plus a minute of clock skew) away. A service token minted without `exp` used to be accepted forever. The Seamless adapters mint them for 60 seconds and are unaffected; a caller that mints its own must set `exp`.
