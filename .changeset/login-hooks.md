---
'seamless-auth-api': minor
---

Add `post_login` and `pre_token` login hooks (ADR 0005, #419).

- Admin API under `/admin/login-hooks/:trigger`: create or replace, read, delete, rotate the signing secret (24 hour overlap), send a test call, and list invocations (kept 30 days). Every write takes step-up and is audited.
- Calls are signed like webhooks, with the invocation id as `webhook-id`, and carry the user, method, organization and request IP and user agent. They never carry a token, code or secret. One attempt, 2 seconds by default and 5 at most.
- `post_login` runs once the factor is proven and before the session exists, and may deny. `pre_token` runs for a new session and on organization switch, and may add claims or deny. Its claims are kept on the session, copied on refresh and to an exchanged session, and dropped when the user leaves the organization they were decided for. Reserved claim names are stripped and audited; the rest are held to 1 KiB.
- Break-glass administrators and recovery sessions never call a hook.
- Contract change: sign-in completion routes and `POST /organizations/:id/switch` can now answer 403 `{ "error": "login_denied", "message"?: "<the hook's userMessage>" }` when a hook denies, and 503 `{ "error": "login_hook_unavailable" }` when a hook set to fail closed times out, answers other than 2xx, or returns a body that does not parse or fit the budget. The hook's `reason` is audited and never returned.
- Access tokens can carry `pre_token` claims beside the existing ones. They can never replace a reserved claim.
- New audit events `login_hook_success`, `login_hook_denied`, `login_hook_failed`, `login_hook_claims_stripped`, `admin_login_hook_set`, `admin_login_hook_deleted` and `admin_login_hook_secret_rotated`.
- `CALLOUT_SECRET_ENCRYPTION_KEY` is now required in production once a login hook exists, as it is for webhooks.
