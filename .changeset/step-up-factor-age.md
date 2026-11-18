---
'seamless-auth-api': minor
---

Step-up and factor enrollment are stricter.

- A step-up only accepts a passkey or TOTP enrolled before the session signed in. One added during the session works from the next sign-in. `/totp/verify-mfa` answers `401 step_up_unavailable` for a TOTP that is too new, and `/step-up/webauthn/start` leaves out passkeys that are too new.
- Passkey and TOTP enrollment, phone registration and recovery code generation need a fresh step-up (`403 step_up_required`) when the account already has a passkey or TOTP. An account with neither needs a sign-in from the last five minutes, and otherwise gets `403 reauthentication_required`. Recovery sessions are exempt.
- `DELETE /users/credentials` needs a fresh step-up.

Clients that add a passkey or TOTP from an existing session should run a step-up when they get `step_up_required`, and ask the user to sign in again when they get `reauthentication_required`.
