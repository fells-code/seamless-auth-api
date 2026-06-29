# seamless-auth-api

## 0.2.2

### Patch Changes

- 03651ba: Harden and regression-test the magic link and OTP sign-in flows.
  - Magic link: polling while waiting now returns `204` (no body) instead of `500`,
    fixing the broken starter sign-in; removed dead device-binding code from verify
    (binding is enforced at the poll step); the post-session write is awaited.
  - OTP: the verify endpoints are now rate-limited; OTPs are stored and compared
    hashed-only (the transitional plaintext fallback is removed); post-session writes
    are awaited.
  - CI: formatting is enforced (`prettier --check`) and coverage thresholds are
    ratcheted so these flows cannot silently regress.

- 3292605: Env-mapped system config (e.g. `LOGIN_METHODS`) now takes effect over
  migration-seeded defaults. Previously the login-policy migration hard-seeded
  `login_methods` and `bootstrapSystemConfig` only seeded missing rows, so the env
  var was permanently ignored. Now bootstrap re-applies env values over config that
  was never changed through the admin API (`updatedBy IS NULL`), admin edits record
  `updatedBy` so they are preserved, and a migration re-applies env to existing
  un-edited rows.
- 6b6f1e6: Apply OAuthProviderConfigSchema defaults to providers configured via OAUTH_PROVIDERS. The
  env value was parsed with a raw JSON.parse, so per-provider fields like subjectJsonPath and
  emailJsonPath stayed undefined and OAuth profile extraction failed with a generic
  "OAuth login failed". The OAuth callback now also logs the underlying error. Fixes #49.

## 0.2.1

### Patch Changes

- 95d321f: Fixed an issue with passing non-valid tokens through to the auth server

## 0.2.0

- Current release baseline before Changesets-managed releases.
