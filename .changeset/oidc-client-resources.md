---
'seamless-auth-api': minor
---

Add `GET /oidc/clients/:id/resources` for the OpenID Provider service: the resources an active application may get access tokens for, each with the scopes it is allowed there (narrowed to what the resource declares) and the resource's access token lifetime. The provider service uses it to issue RFC 9068 JWT access tokens whose `aud` is the resource (RFC 8707). It lists the built-in `<oidc_issuer>/seamless` resource with `notices:send` for an application with notices enabled, so the provider can issue the client credentials token `POST /applications/account-notices` takes. `/oidc/sign` checks the same list. Needs `@seamless-auth/types` with `OidcEdgeRoutes.clientResources`.
