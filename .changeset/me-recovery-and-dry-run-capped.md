---
'seamless-auth-api': patch
---

`GET /users/me` answers `recovery: true` for a recovery session, so a cookie client can route the user back to enrollment after a reload, and `POST /system-config/policy/dry-run` answers `capped: true` when it evaluated only the first 10,000 accounts. The recovery request schemas now come from `@seamless-auth/types` 0.33.0.
