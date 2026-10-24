---
'seamless-auth-api': minor
---

Self-service account recovery through a verified email or phone, with a delay and notices (#399).

- `POST /recovery/start` sends a six-digit code to the verified address on the chosen channel, answering the same whether or not the account has one. `POST /recovery/verify` opens the request, which completes only after `account_recovery.delay`, and tells the account's verified email and phone how to cancel it. `GET /recovery/status` reports `pending`, `ready`, `cancelled` or `completed`.
- `POST /recovery/cancel` takes the token from the notice's link and needs no session. `POST /recovery/complete` on a ready request signs out every session and issues a restricted recovery session.
- A user returning after the delay resumes the request on a new attempt by verifying a fresh code on the same channel.
- Off by default (`ACCOUNT_RECOVERY`). Not blocked by account lockout; five wrong codes void a request. `GET /system-config/public` reports `accountRecovery`.
- Using a recovery code now notifies the account's verified email and phone.
- Migration: new `account_recovery_requests` table.

See docs/account-recovery.md.

Self-service recovery is unavailable in `phishing_resistant_only` mode, since it proves only an address; `GET /system-config/public` reports `accountRecovery: false` there. Cancelling an open request always works.
