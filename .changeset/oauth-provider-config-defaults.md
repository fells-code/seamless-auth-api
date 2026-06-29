---
'seamless-auth-api': patch
---

Apply OAuthProviderConfigSchema defaults to providers configured via OAUTH_PROVIDERS. The
env value was parsed with a raw JSON.parse, so per-provider fields like subjectJsonPath and
emailJsonPath stayed undefined and OAuth profile extraction failed with a generic
"OAuth login failed". The OAuth callback now also logs the underlying error. Fixes #49.
