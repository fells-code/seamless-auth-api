---
'seamless-auth-api': minor
---

Add `POST /applications/account-notices`, so a registered application can tell one of its users something on their verified channels without holding their email or phone. It takes a client credentials token for the built-in `<oidc_issuer>/seamless` resource with scope `notices:send`, which an application can get only after an admin enables notices for it. A notice goes only to a user who holds a grant with that application, as plain text inside a fixed template naming the application and the instance, and an action link must be on one of the application's registered https redirect origins. It is rate limited per application and per user, and writes an `oidc_account_notice_sent` or `oidc_account_notice_failed` auth event. A caller that owns delivery gets `account_notice_email` / `account_notice_sms` payloads back, as on the account recovery routes. A resource can no longer be created with the built-in identifier.
