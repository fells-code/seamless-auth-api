---
'seamless-auth-api': minor
---

Store review accounts: an address listed in `REVIEW_ACCOUNT_EMAILS` is issued `REVIEW_ACCOUNT_CODE` as its email code instead of a random one.

App Store and Google Play reviewers sign in to a demo account and cannot read the inbox a passwordless code goes to. With both variables set, the listed addresses get the configured six-letter code, which can go in the review notes. The code is still stored hashed, expires, is rate limited and is delivered as usual. Boot fails when the addresses are set without a valid code. Both unset, nothing changes.
