---
'seamless-auth-api': minor
---

Adds admin management of OpenID Provider applications (clients) under `/admin/applications` (ADR 0001, D6, D10, D12). Reads need `admin:read`; every write needs `admin:write` and a fresh step-up, and writes an `admin_oidc_application_*` auth event. The routes are access passthroughs in the adapter manifest.

- `GET`, `POST /admin/applications`, and `GET`, `PATCH`, `DELETE /admin/applications/:id`. Deleting an application also deletes its resource grants and every provider grant, code and token issued to it. `disabled: true` keeps the settings but stops sign-in and tokens.
- `POST /admin/applications/:id/secret` issues or rotates a shared secret, shown once and stored only as an HMAC. `PUT /admin/applications/:id/keys` registers a `private_key_jwt` client's JWKS or JWKS URI.
- Insecure settings cannot be created (#410), checked on create and on the merged result of every update. Public clients authenticate with PKCE alone and hold no secret, keys or `client_credentials`. Confidential clients default to `private_key_jwt`. Redirects follow RFC 8252 (#508): exact `https`, `http` only on `127.0.0.1` or `[::1]` with any port at request time, private-use schemes in reverse domain form, and never `localhost`. Shared secrets need `allow_client_secrets`, third-party clients need `third_party_clients_enabled`, and the device grant is first-party only.
- Client metadata served to the provider service no longer reports a `localhost` redirect as native, since one cannot be registered.
- New `hosted_ui` system config key (seeded from `OIDC_HOSTED_UI`, default `null`) for the hosted pages' branding.
