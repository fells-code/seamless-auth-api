---
'seamless-auth-api': minor
---

A response that does not match its declared schema is no longer sent. The API answers `500 { "error": "Internal server error" }` instead, the same body as its error handler, and logs the route and the failing paths. Response schemas are what keep responses minimal, so a payload that breaks one is exactly the one that might carry more than it should.

A route that declares a single response schema now holds only its `200` to it, as the OpenAPI document already said. Error bodies on those routes, such as the `404` from `GET /users/me`, were being checked against the success schema.
