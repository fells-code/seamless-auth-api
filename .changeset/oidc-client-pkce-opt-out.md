---
'seamless-auth-api': minor
---

OpenID Provider applications gain `pkceRequired`, `true` by default and for every existing application. An admin can set it to `false` on a confidential client only (RFC 9700 section 2.1.1), through `POST` or `PATCH /admin/applications`. A public client is refused. The provider service then receives `urn:seamless:pkce_required: false` for that client and requires `nonce` in place of PKCE whenever it asks for an ID token. Each change is recorded as `admin_oidc_application_pkce_updated`. ADR 0001 D1 is amended to match.
