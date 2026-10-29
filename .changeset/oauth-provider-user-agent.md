---
'seamless-auth-api': patch
---

Send a User-Agent on OAuth provider requests in production. The guarded request path sent none, so GitHub answered the profile fetch with 403 and every GitHub sign-in failed.
