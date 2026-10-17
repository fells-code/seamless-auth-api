---
'seamless-auth-api': minor
---

Account lockout no longer takes away a user's passkeys, and `lockoutSeconds` is enforced (GHSA-66gq-4pwg-33jq).

- Passkey sign-in is not subject to lockout, and failed passkey assertions no longer count towards it. An assertion cannot be guessed, and because `/login` issues an ephemeral token from an email address alone, anyone could previously submit wrong OTP codes until an account locked and so shut its owner out of every method, passkeys included.
- `POST /login` for a locked account now continues with `loginMethods: ["passkey"]` when the account has a passkey, and answers `423 account_locked` only when it has none.
- The lock starts at the failure that brings `maxFailures` inside one `windowSeconds` window and lasts `lockoutSeconds` from there. Previously the lock lasted only as long as the failures stayed inside the trailing window, whatever `lockoutSeconds` said, and `retryAfterSeconds` reported `lockoutSeconds` rather than the time actually left. It is now the time left.
- The lockout counter only counts the failure types that lock, so passkey failures recorded before this release stop counting.

An account with no passkey can still be locked by repeated wrong codes, which is what lockout is for. Enrolling a passkey keeps a user able to sign in through a lock someone else triggered.
