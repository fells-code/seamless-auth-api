---
'seamless-auth-api': minor
---

Recovery codes, and restricted recovery sessions (#398).

- `GET /recovery-codes` reports how many of the user's codes are left. `POST /recovery-codes` returns a new set of ten single-use codes (`XXXXX-XXXXX`), the only time they are shown, and invalidates the previous set; replacing a set needs a fresh step-up. Codes are stored as keyed hashes.
- `POST /recovery-codes/redeem`, with the pre-auth token from `/login`, signs in with a code. It is rate limited like an OTP, is not subject to account lockout, and works whatever `login_methods` or `phishing_resistant_only` say. Turned off with `recovery_codes.enabled`.
- The session a code issues is a recovery session: `recovery: true` and `nextStep: "enroll_passkey"` in the response, a `recovery: true` claim in the access token, and `403 enrollment_required` on every access route except passkey and TOTP enrollment, recovery codes, `GET /users/me` and logout, until a new factor is enrolled. Refreshing keeps the restriction; enrolling lifts it.
- `POST /login` lets an account continue to the code when it would otherwise be answered with a lock or a decoy (no passkey, locked or left with no allowed method) and holds an unused code.
- `GET /system-config/public` reports `recoveryCodes`.
- Migration: new `recovery_codes` table, and `sessions.recovery`.

See docs/account-recovery.md.
