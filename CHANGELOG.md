# seamless-auth-api

## 0.2.6

### Patch Changes

- 3cbc491: Build and run the Docker image on Node 24 (`node:24-slim`) to match the
  package's `engines.node` (`>=24 <25`). The image previously used `node:20-slim`,
  which triggered EBADENGINE warnings and could crash the container at startup,
  including in the CLI conformance harness.

## 0.2.5

### Patch Changes

- c71d182: Parse the `FRONTEND_URL` env var as a single string in `parseSystemConfigEnvValue`.
  The `frontend_url` system config was added to the env map and schema but never
  handled by the env parser, so bootstrap threw `Unhandled system config key:
frontend_url` whenever `FRONTEND_URL` was set. Document the variable in
  `.env.example`.

## 0.2.4

### Patch Changes

- f2e3faa: Build the magic-link redirect from a dedicated frontend URL. Add an optional
  `frontend_url` system config (env `FRONTEND_URL`) and use it as the base for
  emailed magic links, falling back to `origins[0]` when unset. Previously the
  link was always built from the first configured origin, which could point at a
  non-frontend origin (for example an API host) depending on origin ordering.

## 0.2.3

### Patch Changes

- 0201af6: Mark `GET /logout` as deprecated in the generated OpenAPI document.

  `defineRoute` now supports a `deprecated` flag that is forwarded to the OpenAPI
  operation. The legacy `GET /logout` route sets it, so consumers and generated
  clients can detect the deprecation and migrate to `DELETE /logout/all`. Runtime
  behavior is unchanged.

- 7d89315: Remove the legacy refresh-token fallback scan.

  Refresh-token lookup now resolves sessions solely by their indexed `refreshTokenLookup`
  fingerprint. The compatibility path that scanned all pre-fingerprint sessions and
  bcrypt-compared each hash on a lookup miss has been removed, along with its per-request
  `Session.findAll` scan. Sessions created before the `refreshTokenLookup` migration are no
  longer refreshable and must re-authenticate; such sessions are long past the refresh-token
  TTL, so no active sessions are affected.

- a236888: Rate limit the `POST /registration/register` endpoint.

  Registration now applies the same per-IP and per-identity limiters already used by
  the OTP and phone-registration routes. This closes an unthrottled path that allowed
  registration/OTP spam and account enumeration against the endpoint.

- ac309bb: Validate `system_config` on the runtime read path.

  `getSystemConfig()` now parses stored configuration against `SystemConfigSchema` on load
  instead of trusting the database rows with a cast. Invalid configuration fails loudly (the
  call throws and the error is logged) rather than flowing malformed values into auth logic.
  Also corrects the cache TTL comment (the value is 5 minutes, not 30 seconds).

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
