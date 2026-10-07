---
'seamless-auth-api': minor
---

Record store review account use and report whether review accounts are on (#331).

- Email code events for an address that is issued the fixed `REVIEW_ACCOUNT_CODE` (`otp_success`, `otp_failed`, `verify_otp_success`, `verify_otp_failed`) now carry `metadata.reviewAccount: true`. The code is never recorded.
- `GET /admin/review-accounts` (admin read) returns `enabled`, the listed `emails`, `codeConfigured` and `recentSignIns` (sign-ins, failed verifications and the last sign-in by a review address in the last `days` days, default 30). The code is never returned.
- Review accounts stay configured by `REVIEW_ACCOUNT_EMAILS` and `REVIEW_ACCOUNT_CODE`.
