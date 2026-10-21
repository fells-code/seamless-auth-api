---
'seamless-auth-api': patch
---

Completing registration with a magic link now claims the account the same way the email code does (GHSA-9xg2-j8fg-427c).

- The address is marked verified (`emailVerified`), since opening the link proves it.
- A phone number verified by a different registration attempt is removed. A phone the same attempt verified, as in phone-first sign up, stays.
- Accounts that were already verified are unchanged.

If `phone_otp` is in `login_methods`, review accounts that finished registration by magic link on an earlier version and whose phone was verified before their email: the phone may not be the owner's. Accounts that never had `phone_otp` enabled are not affected.
