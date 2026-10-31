---
'seamless-auth-api': minor
---

Add `GET /oidc/clients/:id/resources` for the OpenID Provider service: the resources an active application may get access tokens for, each with the scopes it is allowed there (narrowed to what the resource declares) and the resource's access token lifetime. The provider service uses it to issue RFC 9068 JWT access tokens whose `aud` is the resource (RFC 8707). `/oidc/sign` already checks the same links. Needs `@seamless-auth/types` with `OidcEdgeRoutes.clientResources`.
