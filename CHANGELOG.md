# seamless-auth-api

## 1.0.0

### Major Changes

- e9c10b1: Remove the admin bootstrap invite flow. `POST /internal/bootstrap/admin-invite` is gone, along with
  the `bootstrapToken` field on `POST /registration/register`, the `bootstrap_invite_email` external
  delivery kind, the `bootstrap_admin_granted` and `bootstrap_admin_check_skipped` auth event types,
  and the `SEAMLESS_BOOTSTRAP_ENABLED`, `SEAMLESS_BOOTSTRAP_SECRET`, and `SEAMLESS_AUTH_DEBUG_SECRETS`
  environment variables. A migration drops the `bootstrap_invites` table.

  The first admin is now granted through `OWNER_EMAIL`: a user who signs up with a configured owner
  email receives the admin role on account creation.

## 0.5.0

### Minor Changes

- 96e8797: Auto-grant the admin role to a user who signs up with an `OWNER_EMAIL` address.
  Managed instances are provisioned with `OWNER_EMAIL` (the tenant owner, optionally
  a comma separated list); when that user first registers (email/OTP) or signs in
  through a verified OAuth profile, they receive the `admin` role in addition to the
  default roles, provided `admin` is an available role. This makes the bundled
  `/console` admin dashboard usable on a freshly provisioned instance without a
  separate bootstrap-promotion step. The grant is a no-op when `OWNER_EMAIL` is
  unset, so non-managed deployments are unchanged, and it only ever applies to an
  email whose control the signup flow has already verified.

## 0.4.0

### Minor Changes

- 7ea0a9d: Add a `DISABLE_AUTH_RATE_LIMITS` testing escape hatch.

  Beyond the configurable global limiter (`RATE_LIMIT`), dedicated per-IP and
  per-identity limiters guard the OTP, magic-link, registration, and OAuth routes,
  plus JWKS. An automated test or conformance suite driving many of these flows from
  a single IP trips them. Setting `DISABLE_AUTH_RATE_LIMITS=true` now makes every
  auth limiter skip. It is refused under `NODE_ENV=production` (like
  `ALLOW_UNCREDENTIALED_DELIVERY_SECRETS`), so it can never weaken a deployed server.
  Defaults to off.

- 47282ee: Surface actionable OAuth callback failure codes.

  The OAuth callback previously collapsed every profile failure into a generic
  `400 { error: 'OAuth login failed' }`, so a user whose provider returned no email
  (the most common case, for example a GitHub account with no public email) had no
  way to know what to fix. The callback now returns a stable machine-readable `code`
  alongside the existing `error` string for the curated, user-actionable cases:
  `oauth_missing_email`, `oauth_email_not_verified`, and `oauth_missing_subject`.
  Unexpected internal failures still return the generic message with no detail, and
  the audit event records the specific reason instead of the blanket
  `callback_failed` for the known cases.

- 8c218c4: Make admin system-config writes authoritative so they survive a restart.

  Env-mapped `system_config` rows are re-seeded from their environment variable on
  every boot for any row whose `updatedBy` is `NULL`. Admin console writes went
  through the access-token path, which never populated `updatedBy` (only the
  service-token path did), so a change made in the console (for example adding an
  OAuth provider or enabling the `oauth` login method) was silently reverted on the
  next restart, contradicting the documented contract.

  The whole-config `PATCH /system-config/admin` and the per-provider
  `/system-config/oauth-providers` endpoints now record the acting admin's id in
  `updatedBy` on the access-token path, in addition to the existing service-token
  path, so an admin change is genuinely authoritative and is no longer overwritten
  from env. Boot now also logs a warning when it overwrites a stored value that
  differs from the env-derived one, so the reseed is no longer silent.
  `docs/configuration.md` is updated to describe the real precedence.

## 0.3.0

### Minor Changes

- fe78de9: Add admin routes to manage OAuth providers at runtime without hand-editing `system_config` or replacing the whole config array. New endpoints under the existing SystemConfig admin surface: `GET /system-config/oauth-providers` (list), `POST /system-config/oauth-providers` (add, 409 on duplicate id), `PATCH /system-config/oauth-providers/:id` (update, 404 on unknown id), and `DELETE /system-config/oauth-providers/:id` (remove, 404 on unknown id). Each route requires an admin access token (`requireAdmin('read')` for the list, `requireAdmin('write')` for mutations), validates against `OAuthProviderConfigSchema`, invalidates the system-config cache after writes, and records a `system_config_updated` audit event. Client secrets stay out of the API surface: providers continue to reference `clientSecretEnv` and the routes never accept or return a raw secret. Providers remain editable through the existing `PATCH /system-config/admin` whole-array patch, so this is additive.
- 916a3b7: Require a validated internal service token for external delivery in all environments. `canReturnExternalDelivery` no longer treats a non-production `NODE_ENV` as sufficient, so the `x-seamless-auth-delivery-mode: external` header must now be accompanied by an `x-seamless-service-token` that passes issuer, audience, and subject validation. `canReturnSensitiveDevelopmentDetails` is gated the same way. Local development that cannot present a service token can set `ALLOW_UNCREDENTIALED_DELIVERY_SECRETS=true`, an explicit opt-in that is ignored when `NODE_ENV=production`.
- 0005244: Serve the admin dashboard SPA at the `/console` subpath on the API's own origin. Static serving is additive and gated behind `SERVE_ADMIN_DASHBOARD` (enabled by default): the admin API routes are registered first and keep priority, and an SPA history fallback returns the dashboard `index.html` for unmatched `/console` and `/console/*` navigations, with correct MIME types, long-lived immutable caching for hashed assets, and `no-store` on the shell. `/console` is used instead of `/admin` so the SPA namespace never overlaps the admin API under `/admin/*`. The Docker image builds the dashboard from a pinned git ref (the `SEAMLESS_ADMIN_DASHBOARD_REF` build ARG) with base path `/console` and copies it into the runtime image. No CORS changes are needed because the dashboard is same-origin.

### Patch Changes

- 594df9b: Fix response schema handling so a controller response that fails its declared schema is no longer overwritten. Previously the API replaced the real body with a generic `Response validation failed` object and leaked internal Zod issues to clients. It now logs the drift server-side and returns the controller's intended response unchanged.
- ff8067d: Bind the `aud` claim on signed user tokens. `signAccessToken`, `signRefreshToken`, and `signEphemeralToken` now call `.setAudience(ISSUER)` in addition to `.setIssuer(ISSUER)`. The Seamless adapter verifies signed auth responses with `aud === audience`, and the deployment contract requires the adopter's `audience` to equal its `authServerUrl`, which is byte-identical to this server's `ISSUER`. Without the claim, jose rejects every token the adapter checks, so login, registration, OAuth, OTP, magic-link, and organization-switch all fail once the adapter's audience binding ships. The claim is additive and ignored by verifiers that do not check it.

## 0.2.7

### Patch Changes

- 7b33abc: Fix OAuth signup writing a synthetic `oauth:<provider>:<subject>` string into the user's phone field. New OAuth users now have a null phone since the provider supplies no phone number.

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
