---
'seamless-auth-api': patch
---

Raise the default `refresh_token_ttl` from `1h` to `1d`.

`refreshTtl` is the lifetime the server adapter gives the refresh cookie, so a one hour fallback
capped the whole session at one hour no matter how active the user was. An app that holds state
locally and makes no API calls for a couple of hours (a long form, for example) could not refresh
afterwards, so the first save returned 401 and the work was lost. The session row itself already
lives one day (`computeSessionTimes`), so the old fallback also under-reported the real refresh
window.

This changes runtime behavior for any deployment that relied on the fallback or on the shipped
`1h` example value. Refresh tokens are rotated on use and stored hashed, so the longer lifetime is
consistent with the existing session model. Set `REFRESH_TOKEN_TTL` (or the `refresh_token_ttl`
system config row) to keep a shorter window.

The bundled `.env.example` and compose files now ship `REFRESH_TOKEN_TTL=1d` to match.
