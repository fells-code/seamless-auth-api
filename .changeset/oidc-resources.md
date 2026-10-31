---
'seamless-auth-api': minor
---

Adds admin management of OpenID Provider resources and scopes (#509, ADR 0001 D5 and D11). Reads need `admin:read`; every write needs `admin:write` and a fresh step-up, and is audited.

- `GET`, `POST /admin/resources`, and `GET`, `PATCH`, `DELETE /admin/resources/:id`. A resource's identifier is the `aud` of its access tokens, cannot change, and cannot be the API `ISSUER` or `oidc_issuer`. It declares its scopes; the OpenID Connect scopes and `seamless` are reserved. Dropping a scope removes it from every application, and deleting a resource removes it from every application.
- `GET` and `PUT /admin/applications/:id/resources` read and replace the resources and scopes an application may use. Each scope must be one the resource declares. These are the rows `POST /oidc/sign` checks before signing a resource access token.
- New `admin_oidc_resource_created`, `admin_oidc_resource_updated`, `admin_oidc_resource_deleted` and `admin_oidc_application_resources_updated` auth events.
