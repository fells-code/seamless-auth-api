---
'seamless-auth-api': patch
---

Only a verified phone number signs in by phone OTP.

- `POST /login` finds an account by phone only when that phone is verified, and offers `phone_otp` only for a verified phone.
- `/otp/generate-login-phone-otp` answers an unverified phone as it answers an account with no phone (`400`), and `/otp/verify-login-phone-otp` refuses it (`401`).
- The registration phone OTP routes (`/otp/generate-phone-otp`, `/otp/verify-phone-otp`) no longer verify a phone on an account that is already verified. Sending answers `200` and sends nothing; verifying answers `401`. Add or verify a phone on a verified account with an access session through `/registration/phone`.
- The policy dry run counts an unverified phone as no phone.
