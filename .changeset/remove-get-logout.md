---
'seamless-auth-api': minor
---

Remove the deprecated `GET /logout`, which signed out every session of the current user. Use `DELETE /logout/all` for that, or `DELETE /logout` for the current session only. `GET /logout` now answers 404. Every first-party client (`@seamless-auth/server`, `@seamless-auth/react`, `seamless-cli`) already uses `DELETE`. This is a breaking change for any other caller that still sends `GET`.
