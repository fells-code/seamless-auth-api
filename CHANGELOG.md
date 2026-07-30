# seamless-auth-api

## 0.6.0

### Minor Changes

- d248f4e: Make scoped admin roles assignable and discoverable.

  `POST /admin/users` and `PATCH /admin/users/:userId` now reject any role that is not in
  `available_roles` with `400 Invalid roles`, naming the offending roles in `details.roles`.
  Previously a typo like `admin:reed` was accepted and stored, granted nothing because enforcement
  never matches an unlisted role, and reported no error. The match is exact, so wildcards and deeper
  scopes must be listed to be handed out. An empty or unreadable role catalog skips the check rather
  than rejecting every assignment.

  `PATCH /admin/users/:userId` previously returned its `400` through a schema that stripped
  `details`, so the caller could not see what was rejected. Both user endpoints now use a validation
  error schema that carries it, and `POST /admin/users` declares its `400` and `409` responses in
  OpenAPI.

  The `OWNER_EMAIL` grant is now `admin:write` rather than a bare `admin`, stating the owner's
  authority in the scoped vocabulary. Instances whose `available_roles` lists only `admin` still get
  `admin`, which is equivalent in power, so the grant never becomes a no-op.

  `.env.example` now ships `admin:read` and `admin:write` in `AVAILABLE_ROLES` so the console's role
  picker offers read-only admin. `AVAILABLE_ROLES` seeds `available_roles` on first boot only, so
  existing instances need the scoped roles added through the admin system-config endpoints.

- 28d6c22: Support TLS to Postgres. `DB_SSL` (`true`/`false`, or an `sslmode` value such as `require` or
  `verify-full`) and an `sslmode` query parameter on the connection string now set Sequelize's
  `dialectOptions.ssl`, and `DB_SSL_CA` supplies a server CA bundle as inline PEM or a file path.
  Certificate verification follows libpq semantics: `require` encrypts without verifying, `verify-ca`
  and `verify-full` verify, and supplying a CA bundle turns verification on. `DB_SSL_REJECT_UNAUTHORIZED`
  overrides it either way. TLS stays off by default.

  `DB_URI` is now accepted as an alias for `DATABASE_URL`. Connection and TLS resolution is shared
  between the running app and the startup migrations, so a connection string configured without the
  discrete `DB_*` variables no longer breaks migrations.

- 7932ec7: Adopt `@seamless-auth/types@0.4.0` as the source for the shared contract. 88 schema definitions
  across 30 files become re-exports, removing roughly 900 lines of definitions this repo maintained
  in parallel with the SDKs, the dashboard, and the CLI. `roleGrantsAccess`, `hasScopedRole`, and
  `ROLE_NAME_PATTERN` now come from the package too, and the local transport widening shim added
  alongside the passkey fix is gone since the shared `TransportSchema` carries the full WebAuthn set.

  Two response shapes change as a result:
  - Organization and membership `createdAt`/`updatedAt` were `z.any()` and are now typed ISO
    date-times and required. They were always sent; they are now documented accurately.
  - `magic_link_email` delivery marks `token` optional, and anomaly events mark `type` optional,
    matching the shared schemas. Both are still always present in responses.

  Several schemas stay local because the shared versions would lose behavior: the pruned auth event
  list and the query filter built on it, the interval-aware metrics window cap, the timeseries
  `total`/`categories` fields, the grouped-summary `outcomes`, the OTP and magic-link success
  envelope that carries `token` and `delivery`, PRF salt validation, role assignment validation, and
  the JWKS and health responses that no other repo consumes. Each is commented with why.

- 5ecd1f2: Give `POST /login` a single rejection shape and record the server's security posture.

  Every `/login` failure now answers an identical `401 { "error": "Not Allowed" }`. An unknown
  identifier, an unverified account, an account with no permitted continuation method, and a failure
  to mint the pre-auth token previously produced three distinguishable bodies, so an unauthenticated
  caller could tell which case it had hit. The reason is still recorded in the `login_failed` auth
  event metadata, so operators keep the detail.

  The two identifier-lookup failure branches, which fire when the database is unreachable rather
  than when the identifier is unknown, answered `401` on the email path and `403` on the phone path.
  Both now answer `500 { "error": "Server error" }`, so an outage is reported as an outage instead
  of as a failed login.

  `loginMethods` is unchanged on the success response. Removing it buys no enumeration benefit until
  unknown identifiers also receive a decoy token, and dropping it early would degrade legitimate
  clients to a default method list.

  New `docs/security-posture.md` states the deliberate tradeoffs and their mitigating controls: the
  residual enumeration on `/login` and what closing it would take, ephemeral token replay within its
  5 minute TTL, email and phone being plaintext at rest, and the per-deployment `aud` scheme.

- 8ebdc2e: Standardize the error response shape. Every `4xx` and `5xx` response now carries a required
  `error` string, with `message` reserved for optional extra detail, so a consumer reads one field
  to learn why a call failed.

  25 handlers across the WebAuthn, user, internal metrics, dashboard, and security endpoints
  returned `{ message }` with no `error`. They now set `error`. Eight error responses on the
  `/internal/*` routes were declared with `MessageSchema`, which has no `error` field and would have
  stripped it; they now use `ErrorSchema`.

  `InternalErrorSchema` was a byte-identical duplicate of `ErrorSchema` and is now a deprecated alias
  of it. Nothing changes on the wire for the 53 routes that reference it.

  Success responses are untouched: `{ "message": "Success" }` on a `200` is a success payload, not an
  error body.

  A new conformance test walks every registered route and fails if a failure response declares a
  schema without a required `error` string, so a new route cannot reintroduce the split.

- ecaee6b: Prune auth event types that nothing emits, and fix the consumers that searched for them.

  15 of the 74 declared types had no emit site anywhere in `src/`. Five of them were actively
  queried by the security anomaly detector (`bearer_token_failed`, `jwks_failed`, `otp_failed`,
  `recovery_otp_failed`, `user_data_failed`), so those failure categories always returned nothing,
  while `verify_otp_failed`, `totp_failed`, `magic_link_failed`, and `logout_failed` were emitted and
  never searched for. The admin event filter had the same problem: `otp` expanded to a type nothing
  emits and missed every `verify_otp_*` and `mfa_otp_*` event, and `suspicious` named two types that
  are never written.

  Removed: the `bearer_token_*` and `jwks_*` families, `recovery_otp_*`, `user_data_failed`,
  `user_data_success`, `otp_failed`, `mfa_otp_suspicious`, `service_token_suspicious`, and
  `webauthn_login_suspicious`.

  The failure and suspicious groupings are now derived from `AUTH_EVENT_TYPES` instead of being
  hand-copied, so adding an event type files it in the right bucket automatically. A test asserts
  every declared type has an emit site, which is what would have caught the removed `bootstrap_admin_*`
  entries when that feature went away.

  Reading historical rows is unaffected: stored events are returned as `z.string()` and the query
  filter accepts any string, so events recorded under a removed name still appear.

- f7f95dc: Broaden the internal metrics endpoints beyond login success and failure.

  Auth event types are now rolled up into mutually exclusive categories (`suspicious`, `login`,
  `registration`, `webauthn`, `oauth`, `magicLink`, `otp`, `totp`, `stepUp`, `token`, `system`,
  `other`). Previously the grouping matched on substrings in order, so `webauthn_login_success` and
  `oauth_login_success` were counted as plain logins and never appeared in their own buckets.
  - `/internal/auth-events/timeseries` buckets now carry `total` and a `categories` map.
    `success` and `failed` stay login-only, so existing dashboards keep working.
  - `/internal/auth-events/grouped` returns the new categories in `summary` plus an `outcomes`
    roll-up, counts in the database instead of loading every auth event into memory, and accepts
    `from`, `to`, and `userId`.
  - `/internal/auth-events/login-stats` and `/internal/auth-events/summary` accept the same
    `from`, `to`, and `userId` filters as the other metrics endpoints.

  Two date-window fixes: the timeseries used to validate `from`/`to` and then return a now-relative
  window anyway (and with `interval=day` it queried only the last 24 hours while filling 30 daily
  buckets). Buckets now span the requested window. The maximum window is also capped per interval,
  31 days for `hour` and 366 days for `day`, and an open-ended window is measured against the
  current time rather than being unbounded.

- ddf9b41: Generate a real typed client from OpenAPI. `src/generated/api.ts` was an empty
  openapi-typescript stub (`paths = Record<string, never>`) with no way to regenerate it. It now
  carries the full contract, generated from the live route definitions along with a committed
  `openapi.json`.

  `npm run generate:api` produces both. It loads the route modules into a throwaway Express app to
  populate the OpenAPI registry, so no server, environment, or database is needed, and it refuses to
  write an empty spec. Output is prettier-formatted so regenerating never leaves the tree failing
  `format:check`.

  Both artifacts are covered by a test that rebuilds the document and compares it to what is
  committed, so a route or schema change that is not regenerated fails CI instead of silently
  drifting. The comparison ignores `info.version`, which tracks `package.json` and is bumped by
  Changesets on release.

- b3cb4d3: Add a one-command local stack. `docker compose up` now brings up Postgres and the published API
  image together with development defaults, so trying the project no longer means setting up
  Postgres, writing a `.env`, and generating secrets by hand. Migrations run on first boot, a
  development signing keypair is generated, and the admin console is served at
  `http://localhost:5312/console`. `OWNER_EMAIL` defaults to `owner@example.com`, so signing up with
  that address gives a working admin.

  The previous source-built stack moved to `docker-compose.dev.yml` for contributors. It no longer
  requires a `.env` file (one is used when present, and its values win) and it no longer depends on
  a prior `npm run build`, which meant it could not start from a fresh clone. A new `dev:container`
  script runs the watcher without `--env-file`.

  Neither compose file pins `container_name` any more, so a leftover container from an older stack
  no longer blocks startup.

- 81d8ea5: Ship admin dashboard v0.4.0 in the API image.

  `SEAMLESS_ADMIN_DASHBOARD_REF` moves from v0.3.0 to v0.4.0, so the SPA served at `/console` picks
  up that release. It brings keyboard and screen-reader operability across the app shell and charts,
  a step-up path for admins with no passkey, editable organization memberships, inline validation and
  unsaved-changes warnings in system configuration, refresh and export on monitoring, and fixes to
  the user directory, the events view, and sign-in failure messaging.

  The ref is a release tag rather than a floating branch, so the dashboard only changes when this
  value does.

- e9c10b1: Remove the admin bootstrap invite flow. `POST /internal/bootstrap/admin-invite` is gone, along with
  the `bootstrapToken` field on `POST /registration/register`, the `bootstrap_invite_email` external
  delivery kind, the `bootstrap_admin_granted` and `bootstrap_admin_check_skipped` auth event types,
  and the `SEAMLESS_BOOTSTRAP_ENABLED`, `SEAMLESS_BOOTSTRAP_SECRET`, and `SEAMLESS_AUTH_DEBUG_SECRETS`
  environment variables. A migration drops the `bootstrap_invites` table.

  The first admin is now granted through `OWNER_EMAIL`: a user who signs up with a configured owner
  email receives the admin role on account creation.

### Patch Changes

- 81d8ea5: Prune unused dependencies and clear the fixable audit findings.

  Removed three declared dependencies that nothing in the repo imports: `@sequelize/postgres`
  (an alpha of the Sequelize v7 rewrite, which sat in `dependencies` next to `sequelize@6` and
  shipped to the runtime image), `@types/bcrypt` (the code uses `bcrypt-ts`, which carries its own
  types, and a types package does not belong in production dependencies), and `ts-node` (everything
  runs through `tsx`). The production dependency tree drops by 38 packages.

  `tsx` moves to `^4.23.1`, which takes `esbuild ~0.28.0` and so resolves the patched `esbuild`
  0.28.1, and the `allowScripts` pin follows it. Together with `npm audit fix`, this clears the
  `esbuild`, `fast-uri`, `js-yaml`, `tar`, and nested `minimatch` advisories.

  `@types/node` moves to `^24.10.1` to match the `>=24 <25` engine and the pinned Node 24 runtime,
  and `@eslint/js` moves to `^10.0.1` to line up with the already-installed ESLint 10. The ESLint 10
  recommended set adds `preserve-caught-error`, which the log-and-rethrow sites in `src/lib/token.ts`
  and `src/utils/otp.ts` already satisfy, so enabling it needs no further source changes.

  Two advisories are knowingly left in place because neither has a non-breaking fix. `sequelize-cli`
  6.6.5 (the latest) still depends on `js-beautify`, which reaches a vulnerable `brace-expansion`;
  pinning `brace-expansion` to the patched 5.0.8 is not viable because its CJS entry exports
  `{ expand }` while the `minimatch@9` in that chain calls the default export, which would break
  migrations at container start. `sequelize@6` pins `uuid ^8`, and the `uuid` advisory covers only
  `v3`/`v5`/`v6` with a `buf` argument while Sequelize uses `v1` and `v4`, so it is not reachable.

- 870c370: Stop truncating passkey transports. A cross-device passkey reports `hybrid`, older Chrome reported
  `cable`, and security keys can report `smart-card`, but the credential serializer filtered
  `transports` down to the pre-hybrid `usb`/`ble`/`nfc`/`internal` set before building the response.
  Those credentials reported an empty transport list to every client, including `/users/me` and the
  admin user detail view.

  Stored data was never affected: the column is unconstrained JSON and registration writes the value
  through verbatim, so the correct transports come back as soon as the read path stops dropping them.
  No migration or backfill is needed.

  `CredentialResponseSchema` carries a local override widening `transports` to the full WebAuthn set,
  because `@seamless-auth/types@0.1.3` still declares the narrow one. The override and
  `src/lib/authenticatorTransports.ts` can both be deleted once the widened types release is adopted.

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
