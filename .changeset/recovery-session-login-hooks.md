---
'seamless-auth-api': patch
---

A recovery session now runs the `post_login` and `pre_token` login hooks when its restriction lifts, after the user enrolls a passkey or authenticator app. The `pre_token` claims are kept on the session from then on. If a hook refuses, `POST /webauthn/register/finish` and `POST /totp/enroll/verify` answer 403 `login_denied` or 503 `login_hook_unavailable`, and the recovery session is revoked. The new factor is kept, so the user signs in with it, and that sign-in runs the hooks. Break-glass administrators still skip the hooks.
