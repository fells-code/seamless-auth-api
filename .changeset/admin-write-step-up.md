---
'seamless-auth-api': minor
---

Admin writes require a fresh step-up on the calling session (#437).

System config and OAuth provider writes, user create, import, update and delete, admin session revocation, organization admin writes and provider retirement, and `POST /organizations/{organizationId}/members` now run `requireStepUp()` after the admin role check, as device replacement and the audit export already did. Without a WebAuthn or TOTP step-up in the last five minutes they answer `403` with `error: "step_up_required"` and the session's step-up status. Each route documents that `403` in `openapi.json`. Admin reads and enrollment invites are unchanged.

Breaking for scripts and clients that call these routes with a plain admin access token: step up first (`POST /totp/verify-mfa` or `/step-up/webauthn/*` on the same session), then retry. The admin console already steps up before these writes, except organization create and update, which need a console update to prompt first. The CLI's admin write commands fail with a permission error until it learns to step up.
