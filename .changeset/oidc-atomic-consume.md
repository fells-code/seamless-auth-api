---
'seamless-auth-api': minor
---

`POST /oidc/payloads/:model/:id/consume` now answers `200 { consumed }` instead of `204` (`@seamless-auth/types` 0.34.0-next.4). It sets `consumedAt` in one conditional statement, and `consumed` is true only for the call that set it. Two concurrent refreshes with the same refresh token used to both pass the `consumedAt ??=` check and both rotate. Now exactly one wins, and the provider service treats the other as reuse. An expired record is never consumed.
