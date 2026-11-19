---
'seamless-auth-api': patch
---

Session exchange tokens are now signed only for a sign-in. `/oidc/sign` ties each `session:exchange` token to the authorization or device code the edge consumed in the same token request, signs at most one token per code, and refuses a token whose reported grant does not match that code. A refresh grant consumes no code, so it can no longer mint a session exchange token, whatever grant type the edge reports. Session exchange clients are no longer served the `refresh_token` grant, whatever their stored grant list says, and `/oidc/sign` refuses refresh grant tokens for them.
