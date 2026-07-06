---
'seamless-auth-api': patch
---

Mark `GET /logout` as deprecated in the generated OpenAPI document.

`defineRoute` now supports a `deprecated` flag that is forwarded to the OpenAPI
operation. The legacy `GET /logout` route sets it, so consumers and generated
clients can detect the deprecation and migrate to `DELETE /logout/all`. Runtime
behavior is unchanged.
