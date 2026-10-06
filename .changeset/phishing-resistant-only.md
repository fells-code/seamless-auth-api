---
'seamless-auth-api': minor
---

Add a phishing-resistant-only login mode and enforce the passkey fallback rule on every continuation endpoint.

- New `phishing_resistant_only` system config key (env `PHISHING_RESISTANT_ONLY`, default `false`). When on, a session starts only from a passkey: email and phone codes, magic links, TOTP and OAuth are refused with `403 login_method_disabled` (OAuth providers are hidden), whatever `login_methods` says, and the public config reports `loginMethods: ["passkey"]`. The email code that verifies a new account's address still starts one session so the first passkey can be enrolled. Session issuance refuses a non-passkey factor in this mode as a backstop. Requires `@seamless-auth/types` 0.27.0.
- `passkey_login_fallback_enabled: false` now binds on the continuation endpoints themselves, not only on the method list `/login` returns. A user who holds a passkey gets `403 login_method_disabled` from the email and phone code, magic link, TOTP login and email verification endpoints. Previously those endpoints checked only whether the method was enabled for the deployment.
- `POST /totp/verify-login` can now answer `403 login_method_disabled`.
- Decoy responses for unknown identifiers mirror both rules, so the refusals do not reveal whether an account exists.
