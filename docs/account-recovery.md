# Account Recovery

How a user who lost their passkey, or every factor, gets back into their account without an
administrator.

## Recovery codes

A user can generate a set of ten single-use codes, shown once as `XXXXX-XXXXX`.

| Route                         | Auth                                 | What it does                                                               |
| ----------------------------- | ------------------------------------ | -------------------------------------------------------------------------- |
| `GET /recovery-codes`         | access                               | `{ enabled, remaining, total, createdAt }`                                 |
| `POST /recovery-codes`        | access, plus step-up if a set exists | Returns a new set (`201 { codes, createdAt }`) and invalidates the old one |
| `POST /recovery-codes/redeem` | pre-auth token from `/login`         | `{ code }`, accepted with or without the dash and in either case           |

- Codes are stored as HMAC-SHA256 hashes keyed with `REFRESH_TOKEN_LOOKUP_SECRET`, never in
  plain text. A code has 50 bits, which an unkeyed hash from a database dump would not protect.
  Rotating that secret therefore also voids every recovery code.
- Each code works once. Spending one is a conditional update, so two requests with the same
  code cannot both sign in.
- Redeeming is limited by the OTP flow limits but is **not** subject to account lockout, and
  does not count towards it: a code cannot be guessed under those limits, and lockout is
  exactly what someone recovering may be locked out by (see GHSA-66gq-4pwg-33jq for why a
  stranger must not be able to shut an owner out of their way back in).
- Recovery codes are not a login method, so no `login_methods` change can remove them. They
  are turned off only by `recovery_codes.enabled` (`RECOVERY_CODES`), and
  `GET /system-config/public` reports `recoveryCodes` so sign-in screens offer them only
  where they work.
- Audit events: `recovery_codes_generated`, `recovery_code_used` (with the number left) and
  `recovery_code_failed`.

## Recovery sessions

Redeeming a code issues a **recovery session**: the response carries `recovery: true` and
`nextStep: "enroll_passkey"`, and the access token carries a `recovery: true` claim.

Until the user enrolls a new passkey or authenticator app, the API answers
`403 { "error": "enrollment_required" }` on every access route except:

- passkey enrollment (`/webauthn/register/start`, `/webauthn/register/finish`)
- TOTP status and enrollment (`/totp/status`, `/totp/enroll/start`, `/totp/enroll/verify`)
- recovery codes (`GET` and `POST /recovery-codes`)
- `GET /users/me`
- `/logout` and `/logout/all`

The restriction lives on the session row, so refreshing keeps it, and enrolling a factor
lifts it on the very next request. The access token keeps its `recovery` claim until the
client refreshes, so a client should refresh after enrollment. Server adapters refuse a
`recovery: true` token in their `requireAuth` by default, so an application does not treat a
half-recovered account as fully signed in.

A recovery session is allowed in `phishing_resistant_only` mode and when passkey fallback is
off, because enrolling a passkey is all it can do.
