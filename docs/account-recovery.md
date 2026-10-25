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
- An account that `/login` would otherwise answer with a lock or a decoy (no passkey, and
  either locked or left with no method the policy allows) continues with a real pre-auth token
  when it holds an unused code, so the code can be redeemed. The method list it gets is the one
  a decoy would show, so the answer does not single out accounts that hold codes.
- Recovery codes are not a login method, so no `login_methods` change can remove them. They
  are turned off only by `recovery_codes.enabled` (`RECOVERY_CODES`), and
  `GET /system-config/public` reports `recoveryCodes` so sign-in screens offer them only
  where they work.
- Using a code tells the account's verified email and phone, so a code used by someone else
  does not go unnoticed.
- Audit events: `recovery_codes_generated`, `recovery_code_used` (with the number left and
  the outcome of each notice) and `recovery_code_failed`.

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

## Self-service recovery

Off unless `account_recovery.enabled` is true, and always off in `phishing_resistant_only` mode, since it
proves only an email address or phone number. Recovery codes are unaffected. Cancelling an open
request keeps working either way, so turning the feature off never stops an owner stopping one.

For a user with no codes, recovery through a verified email or phone. It cannot complete
quietly: it waits out a delay, and every verified address on the account is told when it
opens, with a link that cancels it.

Off by default. Turn it on with `ACCOUNT_RECOVERY` (`account_recovery`), whose `delay` is
`24h` unless set (`1h` to `30d`). While it is off, every route below answers
`403 { "error": "account_recovery_disabled" }` (except cancelling, and the session routes for
open requests), and `GET /system-config/public` reports
`accountRecovery` so sign-in screens offer it only where it works.

| Route                           | Auth                         | What it does                                                                      |
| ------------------------------- | ---------------------------- | --------------------------------------------------------------------------------- |
| `POST /recovery/start`          | pre-auth token from `/login` | `{ channel: "email" \| "phone" }`, sends a six-digit code                         |
| `POST /recovery/verify`         | the same attempt             | `{ code }`, opens the request and starts the delay                                |
| `GET /recovery/status`          | the same attempt             | `{ state, requestedAt, completesAt }`                                             |
| `POST /recovery/cancel`         | none                         | `{ cancelToken }` from the notice                                                 |
| `POST /recovery/complete`       | the same attempt, once ready | Signs out every session and issues a recovery session                             |
| `GET /recovery/requests`        | access session               | `{ requests: [{ id, channel, state, requestedAt, completesAt }] }`, the open ones |
| `DELETE /recovery/requests/:id` | access session               | Cancels one of them without the token                                             |

### The flow

1. **Start.** The code goes to the verified address on file for the channel, through the
   same delivery as OTP codes (including external delivery, where the response carries
   `delivery`). The answer is the same whether or not the account has a verified address
   there, so it does not say which channels exist. The code lasts ten minutes and is stored
   hashed.
2. **Verify.** Five wrong codes void the request. The right one opens it: `state` is
   `pending`, `completesAt` is now plus the delay, and a notice goes to the account's
   verified email **and** phone saying recovery was requested, when it completes and how to
   cancel it. The cancel link is `${FRONTEND_URL}/recovery/cancel#<token>`; the token is in
   the fragment so it never reaches a server log, and the page posts it to
   `/recovery/cancel`. If no notice is sent to any verified address, the request is voided
   and verify answers `503` with `recovery_notice_failed`: the delay only protects an owner
   who is told about it. Once a notice is sent, any other open request for the account is
   cancelled.
3. **Wait.** `GET /recovery/status` reports `pending` until `completesAt`, then `ready`, or
   `cancelled` or `completed`.
4. **Complete.** On a `ready` request this revokes every session on the account, tells
   both verified addresses, and issues a [recovery session](#recovery-sessions), so the
   user's next step is enrolling a new passkey or authenticator app.

### Coming back after the delay

A pre-auth token lasts minutes and the delay lasts hours, so the user returns on a new
attempt: they sign in with `/login` again, call `/recovery/start` on the **same channel**,
and verify the new code. That resumes the open request on the new attempt with its clock
unchanged and sends no new notice; status and complete then work on that attempt. A code
for a different channel opens a new request instead, with its own delay and notices.

Starting is not enough to disturb anything: anyone who knows an address can start, so only
a verified code opens, resumes or cancels a request. Five wrong codes on a resume void
that code and leave the open request as it was.

### Cancelling

`POST /recovery/cancel` with the token from the notice cancels the request whether it is
`pending` or `ready`. It needs no session, because the owner may be signed out everywhere,
and it answers the same `200` whether or not the token matched, so it is not an oracle.
A signed-in owner can also see open requests with `GET /recovery/requests` and cancel one
with `DELETE /recovery/requests/:id`, without the token. Both work while recovery is turned
off, and a request id from another account answers `404`.

### Notes

- Account lockout does not block recovery, since lockout is what someone recovering may be
  locked out by. Wrong codes are limited per request as above, and every route sits behind
  the OTP flow rate limits.
- A pre-auth token for an identifier with no account gets the answers a real account with
  no verified address gets, and nothing is stored or sent for it.
- Under external delivery the code arrives with `purpose: "account_recovery"`, so an
  adapter can word it as a recovery warning rather than a sign-in code.
- The opening notice goes out directly, through the API's own email or SMS transport,
  unless the caller owns delivery. A credentialed caller that owns delivery (external
  delivery with a service token) gets the notices back only if it lists their kinds in
  `x-seamless-auth-delivery-kinds` (`account_notice_email`, `account_notice_sms`): they
  arrive as `deliveries` on the `/recovery/verify` response, each with `notice:
"account_recovery_opened"` and the `cancelUrl`, and count as notifying the owner. A
  caller that owns delivery but lists neither kind gets the `503`, with each notice
  recorded as `not_sent_external_delivery`, because an adapter that predates the kinds
  would drop them. The adapter manifest marks the route `notices: true`. The delivery
  header alone does not suppress notices, so a stranger cannot recover an account
  silently, and the cancel link is never written to the audit event.
- Audit events: `account_recovery_started`, `account_recovery_verified` (with each notice's
  outcome), `account_recovery_cancelled`, `account_recovery_completed` (with the number of
  sessions revoked) and `account_recovery_failed` (a wrong code, a failed delivery, or a request voided because the
  owner could not be notified).
