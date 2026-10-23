---
'seamless-auth-api': patch
---

The registration email OTP path honours `login_methods` for accounts that are already verified (#470).

- `POST /otp/verify-email-otp` signs an already verified account in only when `email_otp` is a login method (and the passkey rules allow it). Otherwise it answers `403 login_method_disabled` before checking the code, the same answer as `/otp/verify-login-email-otp`. Before, a deployment that removed `email_otp` from `login_methods` could still be signed in to with an email code through this endpoint.
- `POST /otp/generate-email-otp` (and its deprecated `GET`) refuses an already verified account the same way, and its OpenAPI responses now list `403`.
- An unverified account still receives and verifies its registration code whatever `login_methods` says.
- The session is marked as an account verification only when the code actually moved the account from unverified to verified, so the phishing-resistant-only backstop in session issuance stays in force for an existing account.
- Decoy continuations answer both endpoints the same way a verified account is answered.
