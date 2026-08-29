# seamless-auth-api

## 1.0.0

### Major Changes

- 1f5d98c: Require identity proofing on admin-assisted device replacement.

  **Breaking.** `POST /admin/users/:userId/recovery/device-replacement` now
  requires a `proofing` object and answers 400 without one:

  ```json
  {
    "proofing": {
      "method": "in_person",
      "evidenceRef": "TICKET-1042"
    }
  }
  ```

  `method` is `in_person` or `remote_exception`. A remote exception is refused
  unless it names an `approver`, so taking the weaker path is deliberate and
  attributable. `evidenceRef` is a pointer such as a ticket number, not the
  evidence itself, because it is written to the audit trail where identifiers are
  redacted.

  This endpoint revokes every session, removes every passkey and disables TOTP. It
  previously recorded nothing about how the operator established who they were
  talking to, which made a recovery impossible to review afterwards.

  The audit event now carries the proofing record and the acting administrator.
  The acting admin currently rides in event metadata; it moves to a first-class
  column when `auth_events` gains one.

  Callers sending an empty body and relying on the clearing defaults must now send
  proofing. Those defaults are unchanged. Requires `@seamless-auth/types` 0.9.0.

### Minor Changes

- 642b823: Allow hardware security keys to be enrolled.

  `GET /webauthn/register/start` pinned `authenticatorAttachment` to `platform`, which
  hid roaming authenticators from the browser picker entirely, so USB and NFC security
  keys could not be registered at all. Only built-in authenticators (Touch ID, Windows
  Hello, Android biometrics) were reachable.

  Registration now leaves the attachment unset by default, so the browser offers both
  kinds. Callers that want to narrow the picker can pass `?attachment=platform` or
  `?attachment=cross-platform` on `register/start`; anything else is rejected with a 400.

  This changes the default enrolment experience: users who previously saw only the
  built-in authenticator will now also be offered a security key. Deployments that
  genuinely want the old behaviour should pass `?attachment=platform`.

- fdf9613: Correlate audit events to the session they happened in.

  Audit events gain `session_id`, and `GET /admin/auth-events` accepts a
  `sessionId` filter, so a suspicious session can be turned into its event history
  and an event traced back to the session it came from.

  The session is read from the request rather than passed at each of the 135 log
  call sites. The bearer middleware already sets it for any access-token call, so
  authenticated events correlate without any of those sites changing, and anything
  before a session exists stays null. A caller can still name a session
  explicitly, which is what an administrator acting on someone else's session
  needs.

  The column is nullable and not backfilled. The session for historical events is
  unrecoverable.

  Requires `@seamless-auth/types` 0.11.0.

- 30c3971: Record who performed an administrative action.

  Audit events gain `actor_user_id`. An administrator acting on someone else's
  account is now recorded with the target in `user_id` and the administrator in
  `actor_user_id`, so the trail no longer reads as though the user did it to
  themselves. `GET /admin/auth-events` accepts an `actorUserId` filter, which
  answers "what did this administrator do" rather than only "what happened to this
  user".

  Two administrative actions that previously wrote no audit event at all now write
  one:
  - Deleting a user through the admin API
  - Revoking every session for a user

  The user deletion is now awaited before the response, so a failure surfaces as a
  500 rather than a success with the account still present, and the audit event
  records a deletion that actually happened.

  The column is nullable and not backfilled. The actor for historical events is
  genuinely unknown, and inventing one would be worse than leaving it empty.

  Requires `@seamless-auth/types` 0.10.0.

- e58ef6c: Stop recording a WebAuthn registration success before anything is registered.

  `GET /webauthn/register/start` logged `webauthn_registration_success` at the end
  of options generation, before the client had done anything and before any
  credential existed. Every abandoned or failed registration produced a success
  event, so registration counts, dashboards and anomaly detection were all
  measuring the wrong thing. Because outcome is derived from the `_success`
  suffix, those events were also counted as successful WebAuthn activity in the
  metrics.

  Issuing options now logs `webauthn_registration_challenge`, matching
  `login_challenge` on the login path. It categorises as `webauthn` with outcome
  `other`, so it no longer inflates the success figures. The real
  `registration_success` stays where it belongs, on verified registration in
  `/webauthn/register/finish`.

  `webauthn_registration_success` is removed from the declared event types, since
  it is now emitted nowhere and this repository deliberately prunes types nobody
  writes so consumers do not filter and alert on names that never arrive. Stored
  events keep that type and remain readable and filterable by exact type; they are
  no longer swept into the `webauthn` category filter.

- 15005f2: Make session lifetimes configurable, and give the idle bound a chance to fire.

  Session expiry came from two hardcoded constants, both one day. Because they
  were equal, `idleExpiresAt` and `expiresAt` always landed on the same instant,
  so the idle bound could never fire before absolute expiry. In practice there was
  no idle timeout at all, despite the session model carrying the column and the
  lookup queries filtering on it.

  Two changes:
  - The absolute session lifetime now comes from `refresh_token_ttl`, which
    already existed and was already reported to clients as `refreshTtl`. It was
    not previously applied to the session row, so an instance with
    `REFRESH_TOKEN_TTL=30d` told clients thirty days and expired the session after
    one. Setting it now does what it says.
  - The idle bound comes from the new `session_idle_ttl`
    (`SESSION_IDLE_TTL`), default `8h`.

  **Behaviour change.** On stock configuration a session that goes unrefreshed
  now ends after 8 hours rather than 24. Any client refreshing normally is
  unaffected, because rotation resets the bound and access tokens are far shorter
  lived; only genuinely idle sessions end sooner. Instances that want the previous
  behaviour can set `SESSION_IDLE_TTL=1d`, and deployments with a stricter posture
  typically want 15m to 30m.

  An instance that previously relied on `REFRESH_TOKEN_TTL` being longer than one
  day will see sessions live as long as that value now actually says, which is
  longer than before. Check that value if it was set to something large on the
  assumption it was inert.

  Requires `@seamless-auth/types` 0.8.0.

- 429cfd2: Let a deployment choose which authenticators it will enrol.

  Adds the `authenticator_policy` system config key, settable from
  `AUTHENTICATOR_POLICY` as JSON:

  ```json
  { "attachment": "any" }
  ```

  `attachment` accepts `any`, `platform` or `cross-platform`. `any`, the default,
  offers both built-in authenticators and roaming security keys at registration,
  which is what an agency issuing hardware keys needs. Naming one narrows the
  browser picker for every registration on the instance.

  The `?attachment=` parameter on `GET /webauthn/register/start` still works, and
  is now bounded by the policy: a request asking for a kind a pinned policy
  excludes is refused with `400 { "error": "attachment_not_allowed" }` rather than
  silently overriding it. A request that agrees with the policy is fine.

  Existing deployments are unaffected. The key defaults to `{ "attachment": "any" }`,
  which is the behaviour they already had.

  Requires `@seamless-auth/types` 0.7.0, which carries the shared schema.

### Patch Changes

- 52503b3: Resolve the high severity advisories in the dependency tree.

  `npm audit fix` cleared six high severity findings, all transitive, with no
  change to `package.json` and no change in behaviour. Two moderate advisories
  remain from `sequelize`, whose only offered fix is a downgrade to version 3.

## 0.7.4

### Patch Changes

- 7b8b6c2: Add `TRUST_PROXY` so the client address can be read from `X-Forwarded-For`.

  Express leaves `trust proxy` off by default, so behind a load balancer `req.ip` resolved to the
  balancer rather than the caller. Every client shared one bucket in the global rate limiter and the
  slow-down middleware, and `express-rate-limit` logged an `ERR_ERL_UNEXPECTED_X_FORWARDED_FOR`
  validation error on each request. Set `TRUST_PROXY` to the number of proxies in front of the server
  (`1` behind a single load balancer) to restore per-client limiting. It stays unset by default
  because a directly reachable server that trusts the header lets a client forge its own address.

## 0.7.3

### Patch Changes

- 9c379b0: Drop the orphaned bootstrap secret check from the container entrypoint.

  `validateEnvs.sh` still required `SEAMLESS_BOOTSTRAP_SECRET` whenever `SEAMLESS_BOOTSTRAP_ENABLED`
  was `true`. Both variables were removed with the admin bootstrap invite flow, so nothing in the
  runtime reads either one. A deployment that carried the old `SEAMLESS_BOOTSTRAP_ENABLED=true` over
  from a previous release refused to boot until it supplied a secret that no longer did anything.

## 0.7.2

### Patch Changes

- 892e616: Raise the default `refresh_token_ttl` from `1h` to `1d`.

  `refreshTtl` is the lifetime the server adapter gives the refresh cookie, so a one hour fallback
  capped the whole session at one hour no matter how active the user was. An app that holds state
  locally and makes no API calls for a couple of hours (a long form, for example) could not refresh
  afterwards, so the first save returned 401 and the work was lost. The session row itself already
  lives one day (`computeSessionTimes`), so the old fallback also under-reported the real refresh
  window.

  This changes runtime behavior for any deployment that relied on the fallback or on the shipped
  `1h` example value. Refresh tokens are rotated on use and stored hashed, so the longer lifetime is
  consistent with the existing session model. Set `REFRESH_TOKEN_TTL` (or the `refresh_token_ttl`
  system config row) to keep a shorter window.

  The bundled `.env.example` and compose files now ship `REFRESH_TOKEN_TTL=1d` to match.

## 0.7.1

### Patch Changes

- 381d87e: Send the registration response's `ttl` as a number.

  It was the string `'300'`, the only `ttl` this API sends that was not a number. A caller sets its
  registration cookie from it, and the Fastify adapter passes the value to a cookie library that
  requires an integer, so registration failed there with `TypeError: option maxAge is invalid: 300`.
  The Express adapter multiplies it into milliseconds, which coerces the string, so the same response
  worked and the mismatch went unnoticed.

  Requires `@seamless-auth/types` 0.6.0, where `RegistrationSuccessSchema.ttl` becomes a number.
  Response bodies are validated against that schema at runtime, so the two move together.

## 0.7.0

### Minor Changes

- 6bd56c4: Serve the publicly visible system configuration from an unauthenticated `GET /system-config/public`.

  It returns the configured `loginMethods` and nothing else. The bundled sign-in screens in the SDKs
  render before anyone has a session, so they cannot read the configuration and today fall back to a
  hardcoded list of methods. That list can advertise a method an instance has turned off. This lets a
  client ask instead.

  It also unblocks offering a skip on passkey registration, which is only safe when another login
  method is enabled. A client that cannot see the method list cannot make that call safely.

  The handler reads through `getLoginPolicy`, so a tainted or partially written config answers with
  the defaults rather than failing. A signed-out client with no methods has nothing to render, and a
  500 here would take the sign-in screen down with it.

  Every other key in the system configuration stays behind the admin routes.

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
