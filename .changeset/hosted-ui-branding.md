---
'seamless-auth-api': minor
---

`GET /oidc/config` returns `hostedUi`, the `hosted_ui` branding from system config, when one is set, so the OpenID Provider service brands its hosted login and consent pages from the API. Admins set and clear it through `PATCH /system-config/admin` (admin write, step-up required), which validates it against `@seamless-auth/types` and refreshes the cached config. Branding values are validated tightly because the hosted pages serve them under a strict nonce CSP: hex colors only, an https `logoUrl` with no credentials, quotes, parentheses, spaces or semicolons, and a font stack of plain or single-quoted font names.
