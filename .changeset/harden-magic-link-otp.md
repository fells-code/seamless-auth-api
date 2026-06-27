---
'seamless-auth-api': patch
---

Harden and regression-test the magic link and OTP sign-in flows.

- Magic link: polling while waiting now returns `204` (no body) instead of `500`,
  fixing the broken starter sign-in; removed dead device-binding code from verify
  (binding is enforced at the poll step); the post-session write is awaited.
- OTP: the verify endpoints are now rate-limited; OTPs are stored and compared
  hashed-only (the transitional plaintext fallback is removed); post-session writes
  are awaited.
- CI: formatting is enforced (`prettier --check`) and coverage thresholds are
  ratcheted so these flows cannot silently regress.
