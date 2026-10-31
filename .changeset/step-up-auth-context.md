---
'seamless-auth-api': minor
---

Step-up now counts as an authentication for the OpenID Provider. A passkey step-up (`/step-up/webauthn/finish`) or a TOTP step-up (`/totp/verify-mfa`) adds its method to the session's `authMethods` (a passkey with its device binding and user verification) and moves `authTime` to the step-up, so `acr`, `amr` and `auth_time` reflect it. A repeated method replaces its earlier record rather than adding another. `GET /oidc/sessions/:id/auth-context` now reports the current row of the session's refresh chain, which is where step-up records and what `/oidc/sign` checks, so a session refreshed before stepping up reports the step-up too.
