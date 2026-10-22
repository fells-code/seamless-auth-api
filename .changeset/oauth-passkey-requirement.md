---
'seamless-auth-api': patch
---

OAuth sign-in respects the per-account passkey requirement (#469).

- With `passkey_login_fallback_enabled` off, `POST /oauth/:providerId/callback` for an account that holds a passkey now answers `403 login_method_disabled` and issues no session, as the email code, phone code, magic link and TOTP continuations already did. The refusal is recorded as `oauth_login_failed` with reason `passkey_required`.
- Session issuance now applies the same rule as its backstop, not only phishing-resistant-only mode, so a sign-in path that misses the check fails closed instead of issuing a session.
