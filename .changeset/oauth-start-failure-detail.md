---
'seamless-auth-api': patch
---

A failed OAuth start now says why. The `oauth_login_failed` event with reason `start_failed` carries a `detail` of `redirect_not_allowed` or `provider_unusable`, and the error is logged with the provider id. A refused redirect is logged by scheme and host only. The answer to the client is unchanged.
