# Configuration Reference

This is the single source of truth for how Seamless Auth API is configured. It lists every
environment variable, whether it is required, its default, and where it takes effect.

There are two configuration layers:

- **Environment variables** boot the process, connect external systems (database, messaging,
  signing keys), and seed the runtime config on first start.
- **`system_config` table** holds runtime settings (token TTLs, roles, origins, login methods,
  OAuth providers, rate limits). These are seeded from environment variables on first boot and
  are the source of truth afterwards.

> Once an admin changes an env-mapped value through the admin system-config endpoints, that row
> becomes authoritative and its environment variable is no longer consulted. Until then, the env
> var is re-applied on every boot. See [Environment vs system_config](#environment-vs-system_config).

## Minimal configuration to boot

For local development, these are the only values you must set (all are present in
[`.env.example`](../.env.example) with working defaults):

| Variable              | Example                 | Purpose                                           |
| --------------------- | ----------------------- | ------------------------------------------------- |
| `APP_NAME`            | `Seamless Auth Example` | Human-readable app name (min 3 chars)             |
| `APP_ID`              | `local-dev`             | Stable application identifier                     |
| `APP_ORIGINS`         | `http://localhost:3000` | Callers allowed by CORS                           |
| `ISSUER`              | `http://localhost:5312` | JWT `iss` claim and issuer URL                    |
| `DEFAULT_ROLES`       | `user`                  | Roles assigned to every new user                  |
| `AVAILABLE_ROLES`     | `user,admin`            | Roles allowed in the system                       |
| `ACCESS_TOKEN_TTL`    | `30m`                   | Access token lifetime (`\d+[smhd]`)               |
| `REFRESH_TOKEN_TTL`   | `1d`                    | Refresh token lifetime (`\d+[smhd]`)              |
| `RATE_LIMIT`          | `100`                   | Global request rate limit                         |
| `DELAY_AFTER`         | `50`                    | Requests before slow-down kicks in                |
| `RPID`                | `localhost`             | WebAuthn relying party ID                         |
| `ORIGINS`             | `http://localhost:5173` | WebAuthn allowed origins (comma-separated)        |
| `API_SERVICE_TOKEN`   | `<32-byte hex>`         | Trusted server-adapter and internal bearer secret |
| Database connectivity | see below               | `DATABASE_URL`/`DB_URI` **or** the `DB_*` set     |

Everything else is optional or environment-specific.

The container entrypoint validates these at startup via
[`validateEnvs.sh`](../validateEnvs.sh) and exits with a clear message if one is missing.

## Environment variables

Legend: **Required** = process refuses to boot without it (enforced by `validateEnvs.sh` in the
container path). **Seeds `system_config`** = value is copied into the runtime config table on
first boot.

### Application

| Variable          | Required | Default       | Seeds `system_config` | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ----------------- | -------- | ------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `NODE_ENV`        | No       | `development` | No                    | `production` enables stricter checks (JWKS, secrets).                                                                                                                                                                                                                                                                                                                                                                                      |
| `HOST`            | No       | `0.0.0.0`     | No                    | Bind address.                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `PORT`            | No       | `5312`        | No                    | Listen port.                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `TRUST_PROXY`     | No       | unset         | No                    | Express `trust proxy` value, used to read the client address from `X-Forwarded-For`. Set it to the number of proxies in front of the server (`1` behind a single load balancer); `loopback` and a comma-separated IP/CIDR allowlist also work. Without it the rate limiters bucket every client behind the proxy together. Leave it unset when the server is reachable directly, or a client can forge the header and pick its own bucket. |
| `APP_NAME`        | Yes      | -             | `app_name`            | Min 3 characters.                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `APP_ID`          | Yes      | -             | No                    | Stable app identifier.                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `APP_ORIGINS`     | Yes      | -             | No                    | CORS allowlist for callers of this API (comma-separated). Distinct from WebAuthn `ORIGINS`.                                                                                                                                                                                                                                                                                                                                                |
| `ISSUER`          | Yes      | -             | No                    | JWT `iss` and issuer URL.                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `DEFAULT_ROLES`   | Yes      | -             | `default_roles`       | Roles for new users (comma-separated).                                                                                                                                                                                                                                                                                                                                                                                                     |
| `AVAILABLE_ROLES` | Yes      | -             | `available_roles`     | Roles permitted in the system (comma-separated). Assigning a role that is not listed is rejected. Include `admin:read` and `admin:write` to offer scoped admin. See [Scoped Admin Roles](./admin-operations.md#scoped-admin-roles).                                                                                                                                                                                                        |

### Auth and tokens

| Variable                         | Required | Default                                                                      | Seeds `system_config`            | Notes                                                                                                                                                                                                                                       |
| -------------------------------- | -------- | ---------------------------------------------------------------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ACCESS_TOKEN_TTL`               | Yes      | -                                                                            | `access_token_ttl`               | Format `\d+[smhd]`, e.g. `30m`.                                                                                                                                                                                                             |
| `REFRESH_TOKEN_TTL`              | Yes      | -                                                                            | `refresh_token_ttl`              | Format `\d+[smhd]`, e.g. `1d`. Falls back to `1d` when unset.                                                                                                                                                                               |
| `RATE_LIMIT`                     | Yes      | -                                                                            | `rate_limit`                     | Global limit, positive integer.                                                                                                                                                                                                             |
| `DELAY_AFTER`                    | Yes      | -                                                                            | `delay_after`                    | Slow-down threshold, non-negative integer.                                                                                                                                                                                                  |
| `LOGIN_METHODS`                  | No       | `passkey,magic_link`                                                         | `login_methods`                  | Any of `passkey,magic_link,email_otp,phone_otp,oauth`. `.env.example` ships `passkey,magic_link,email_otp` so a stock instance is CLI/headless-loginable; `email_otp` needs a configured messaging transport or the external-delivery path. |
| `PASSKEY_LOGIN_FALLBACK_ENABLED` | No       | `true`                                                                       | `passkey_login_fallback_enabled` | When `false`, passkey-capable sessions continue with passkey only.                                                                                                                                                                          |
| `LOCKOUT_POLICY`                 | No       | `{"enabled":true,"maxFailures":10,"windowSeconds":900,"lockoutSeconds":900}` | `lockout_policy`                 | JSON. Set `enabled:false` only when an upstream policy handles lockout.                                                                                                                                                                     |

### Service tokens and secrets

| Variable                      | Required | Default                           | Notes                                                                                                               |
| ----------------------------- | -------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `API_SERVICE_TOKEN`           | Yes      | -                                 | Trusted server-adapter and internal bearer secret. Also the fallback for the two secrets below.                     |
| `REFRESH_TOKEN_LOOKUP_SECRET` | No       | falls back to `API_SERVICE_TOKEN` | HMAC key for indexed refresh-token lookup fingerprints. In development only, an unset value derives a local secret. |
| `TOTP_SECRET_ENCRYPTION_KEY`  | No       | falls back to `API_SERVICE_TOKEN` | 32-byte base64url/base64/hex key for encrypted TOTP secrets. Production requires this or `API_SERVICE_TOKEN`.       |
| `OAUTH_STATE_SECRET`          | No       | falls back to `API_SERVICE_TOKEN` | Dedicated signing secret for OAuth state.                                                                           |

> Prefer setting dedicated secrets in production rather than relying on the `API_SERVICE_TOKEN`
> fallbacks. See [docs/production-operations.md](./production-operations.md).

### Database

Provide **either** a connection string (`DATABASE_URL`, or `DB_URI` as an alias) **or** the
discrete `DB_*` variables. A connection string wins when set and is preferred in containers and
hosted environments. The same resolution is shared by the running app and by the startup
migrations, so both connect the same way.

| Variable       | Required    | Default         | Notes                                                                         |
| -------------- | ----------- | --------------- | ----------------------------------------------------------------------------- |
| `DATABASE_URL` | Conditional | -               | Full Postgres connection string. If set, the `DB_*` host set is not required. |
| `DB_URI`       | Conditional | -               | Alias for `DATABASE_URL`, used when `DATABASE_URL` is unset.                  |
| `DB_HOST`      | Conditional | `localhost`     | Required when no connection string is set.                                    |
| `DB_PORT`      | Conditional | `5432`          | Required when no connection string is set.                                    |
| `DB_NAME`      | Conditional | `seamless_auth` | Required when no connection string is set.                                    |
| `DB_USER`      | Conditional | -               | Required when no connection string is set.                                    |
| `DB_PASSWORD`  | No          | -               | Password for `DB_USER`.                                                       |
| `DB_LOGGING`   | Yes         | `false`         | Logs SQL from the app and startup migrations.                                 |

#### TLS to Postgres

TLS is **off by default**, which suits a local Postgres on loopback. Managed databases should
turn it on, and it is mandatory when the cluster enforces it (for example Aurora/RDS with
`rds.force_ssl = 1`).

| Variable                     | Required | Default   | Notes                                                                                            |
| ---------------------------- | -------- | --------- | ------------------------------------------------------------------------------------------------ |
| `DB_SSL`                     | No       | off       | `true`/`false`, or an `sslmode` value: `require`, `prefer`, `allow`, `verify-ca`, `verify-full`. |
| `DB_SSL_CA`                  | No       | -         | Server CA bundle, inline PEM or a file path. Supplying it turns certificate verification on.     |
| `DB_SSL_REJECT_UNAUTHORIZED` | No       | see below | Forces certificate verification on or off, overriding the default for the selected mode.         |

Resolution order:

1. `DB_SSL` wins when set.
2. Otherwise an `sslmode` query parameter on the connection string is honored.
3. Otherwise TLS is off.

Certificate verification follows libpq semantics: `require` (and `DB_SSL=true`) encrypts without
verifying the server certificate, while `verify-ca` and `verify-full` verify it. Verification is
also enabled whenever `DB_SSL_CA` is supplied. Amazon's RDS certificates chain to a private CA
that Node does not trust by default, so verifying against RDS means pointing `DB_SSL_CA` at the
RDS global bundle.

### WebAuthn

| Variable  | Required | Default | Seeds `system_config` | Notes                                                                                                                                                                                                                                        |
| --------- | -------- | ------- | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `RPID`    | Yes      | -       | `rpid`                | Relying party ID (a domain, no scheme).                                                                                                                                                                                                      |
| `ORIGINS` | Yes      | -       | `origins`             | WebAuthn allowed origins (comma-separated URLs). Distinct from `APP_ORIGINS`. When you serve the admin console, the origin it loads from must also appear here, alongside the app origins. See [Admin dashboard](#admin-dashboard-optional). |

### OAuth

| Variable          | Required | Default | Seeds `system_config` | Notes                                                                                                                                                                                             |
| ----------------- | -------- | ------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `OAUTH_PROVIDERS` | No       | `[]`    | `oauth_providers`     | JSON array of provider configs. Provider client secrets stay in env vars referenced by each provider's `clientSecretEnv`, never in this JSON or `system_config`. See [docs/oauth.md](./oauth.md). |

### First admin

| Variable      | Required | Default | Notes                                                                                                                      |
| ------------- | -------- | ------- | -------------------------------------------------------------------------------------------------------------------------- |
| `OWNER_EMAIL` | No       | -       | Comma separated list of tenant owner emails. A user who signs up with one of these is granted `admin` on account creation. |

The grant is safe because both signup paths establish control of the email before the account is
created (email OTP verification, or a verified OAuth profile), so only someone who actually receives
mail at the owner address can claim it. When `OWNER_EMAIL` is unset the grant is a no-op and the
instance has no admin until one is assigned another way.

### Admin dashboard (optional)

This API can serve the admin dashboard SPA ([`seamless-auth-admin-dashboard`](https://github.com/fells-code/seamless-auth-admin-dashboard))
at the `/console` subpath on its own origin (same origin as the API), so a managed instance ships
its dashboard without a separate host. Serving is additive: the admin API routes are registered
first and keep priority, and the SPA history fallback only handles unmatched `/console/*` GETs. No
CORS changes are needed because the dashboard is same-origin with the API.

`/console` is chosen deliberately so the SPA namespace never overlaps the admin API, which lives
under `/admin/*` (`/admin/users`, `/admin/organizations`, `/admin/sessions`, `/admin/audit-events`,
`/admin/credential-count`). A path under `/admin` would let a hard refresh or deep-link on one of
those routes resolve to the API instead of the SPA; `/console` has no such overlap.

| Variable                | Required | Default             | Notes                                                                                                             |
| ----------------------- | -------- | ------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `SERVE_ADMIN_DASHBOARD` | No       | `true`              | Serve the SPA at `/console`. Set to `false` to disable. When enabled but no build is bundled, serving is skipped. |
| `ADMIN_DASHBOARD_DIR`   | No       | `./admin-dashboard` | Directory of the built SPA, relative to the compiled bundle. The Docker image copies the dashboard build here.    |

**Build integration and version bumps.** The dashboard repo is public, but its npm package is
not published (`"private": true` in its `package.json`), so the Docker image fetches it from git
at a pinned ref and runs the dashboard's own same-origin build (`npm run build:console`, which
sets `VITE_BASE_PATH=/console/` and `VITE_SAME_ORIGIN=true` so the assets, the router basename,
and the origin-derived API base all agree) in a dedicated stage (see the `admin-dashboard` stage
in [`Dockerfile`](../Dockerfile)). Bump the dashboard shipped to tenants by raising the
`SEAMLESS_ADMIN_DASHBOARD_REF` build ARG; the new version then flows to tenants through the normal
upstream auth-image release. The ref is pinned to the dashboard release tag `v0.2.0`, the first
release that ships the same-origin `/console` build.

Because the same-origin build derives its API base from the page origin **and still speaks the
server-adapter contract** (it calls `<origin>/auth/...` with `credentials: include`), the origin
that serves `/console` must also expose the `@seamless-auth/express` adapter's `/auth/*` cookie
endpoints. This bare API is Bearer-only with no `/auth` prefix and no cookies, so loading the SPA
directly from the API origin renders the UI but its API calls fail.

The supported wiring is `@seamless-auth/express` (>= 0.8.0), which serves the dashboard and the
adapter from one origin: mount the console reverse-proxy alongside the auth routes so `/console`
is proxied to this API while `/auth/*` is handled by the adapter.

```js
app.use('/auth', createSeamlessAuthServer(opts));
app.use('/console', createSeamlessConsoleProxy({ authServerUrl: opts.authServerUrl }));
```

The proxy forwards `/console` requests to this API's `/console` (so the dashboard version tracks
the auth image), while the adapter bridges the dashboard's cookie session to Bearer upstream.

**Prerequisites for browser flows started from the console.** Serving the console changes the
origin that passkey ceremonies carry, and for OAuth it changes the full redirect URI. Two separate
allowlists validate these, and both fail the same confusing way: the flow starts normally and only
fails partway through, so the configuration looks correct right up to the point it does not work.
Both apply to both deployment shapes above (served directly by this API at its own origin, or
reverse-proxied through `createSeamlessConsoleProxy` at the adopter's origin).

1. **The console's origin must be in `ORIGINS`.** Passkey and step-up ceremonies started in the
   console carry the origin the console was loaded from, and WebAuthn verification checks it against
   `origins` in `system_config` (seeded from `ORIGINS`). If it is missing, `start` returns 200 with
   a challenge and the browser prompts normally, but `finish` fails, so step-up never completes.
   Add the console's origin (for example `https://api.example.com`) to `ORIGINS` alongside the app
   origins. `RPID` does not need to change, since the RP ID ignores the port.

2. **The console's callback must be in each provider's `redirectUris`.** The dashboard builds its
   OAuth redirect with the router basename applied, so the `/console` build sends
   `<origin>/console/oauth/callback`, a different path (and host) from a typical web app's
   `/oauth/callback`. `redirectUris` is matched exactly, so this URL must be listed explicitly on
   each provider, and it must also be registered as an authorized redirect URI with the identity
   provider itself. If it is missing here, `POST /oauth/:providerId/start` returns 400 before any
   redirect; if it is missing at the provider, the provider rejects with `redirect_uri_mismatch` at
   the consent screen. See [docs/oauth.md](./oauth.md).

### Direct messaging (optional)

Needed only when this API sends OTP/magic-link messages itself. Not needed when a SeamlessAuth
server adapter handles delivery in external mode. `validateEnvs.sh` enforces provider-specific
combinations (for example, Twilio requires SID, auth token, and a from-number).

| Variable                       | Required      | Default     | Notes                                                      |
| ------------------------------ | ------------- | ----------- | ---------------------------------------------------------- |
| `MESSAGING_ENABLE_IN_DEV`      | No (dev only) | `false`     | Exercise direct delivery even when `NODE_ENV=development`. |
| `MESSAGING_AWS_REGION`         | Conditional   | `us-east-1` | Required when email-from is set or SMS provider is `aws`.  |
| `MESSAGING_EMAIL_FROM`         | Conditional   | -           | Enables email delivery when set.                           |
| `MESSAGING_SMS_PROVIDER`       | No            | -           | `aws` or `twilio`.                                         |
| `MESSAGING_SMS_FROM`           | Conditional   | -           | Required for Twilio.                                       |
| `MESSAGING_TWILIO_ACCOUNT_SID` | Conditional   | -           | Required for Twilio.                                       |
| `MESSAGING_TWILIO_AUTH_TOKEN`  | Conditional   | -           | Required for Twilio.                                       |

### Production signing and JWKS

Required when `NODE_ENV=production`. In development, signing keys are generated locally.

| Variable                          | Required  | Default | Notes                                                                              |
| --------------------------------- | --------- | ------- | ---------------------------------------------------------------------------------- |
| `SEAMLESS_JWKS_ACTIVE_KID`        | Prod only | -       | Key ID of the active signing key.                                                  |
| `SEAMLESS_JWKS_KEY_<KID>_PRIVATE` | Prod only | -       | PKCS8 private key PEM for the active KID.                                          |
| `JWKS_PUBLIC_KEYS`                | Prod only | -       | JSON `{ "keys": [{ "kid", "pem", "createdAt" }] }` published at the JWKS endpoint. |

See [docs/production-operations.md](./production-operations.md) for key rotation.

## `system_config` keys

These runtime values live in the `system_config` table. On first boot,
[`bootstrapSystemConfig.ts`](../src/config/bootstrapSystemConfig.ts) seeds any missing key from
its mapped environment variable ([`systemConfig.envMap.ts`](../src/config/systemConfig.envMap.ts))
or from a built-in default ([`systemConfig.defaults.ts`](../src/config/systemConfig.defaults.ts)).
Validation is enforced by [`systemConfig.schema.ts`](../src/schemas/systemConfig.schema.ts).

| Key                              | Type                 | Seeded from env                  | Default                                                         |
| -------------------------------- | -------------------- | -------------------------------- | --------------------------------------------------------------- |
| `app_name`                       | string (min 3)       | `APP_NAME`                       | -                                                               |
| `default_roles`                  | string[]             | `DEFAULT_ROLES`                  | -                                                               |
| `available_roles`                | string[]             | `AVAILABLE_ROLES`                | -                                                               |
| `login_methods`                  | enum[]               | `LOGIN_METHODS`                  | `["passkey","magic_link"]`                                      |
| `passkey_login_fallback_enabled` | boolean              | `PASSKEY_LOGIN_FALLBACK_ENABLED` | `true`                                                          |
| `oauth_providers`                | provider[]           | `OAUTH_PROVIDERS`                | `[]`                                                            |
| `lockout_policy`                 | object               | `LOCKOUT_POLICY`                 | `{enabled,maxFailures:10,windowSeconds:900,lockoutSeconds:900}` |
| `access_token_ttl`               | string (`\d+[smhd]`) | `ACCESS_TOKEN_TTL`               | -                                                               |
| `refresh_token_ttl`              | string (`\d+[smhd]`) | `REFRESH_TOKEN_TTL`              | -                                                               |
| `rate_limit`                     | integer > 0          | `RATE_LIMIT`                     | -                                                               |
| `delay_after`                    | integer >= 0         | `DELAY_AFTER`                    | -                                                               |
| `rpid`                           | string               | `RPID`                           | -                                                               |
| `origins`                        | url[]                | `ORIGINS`                        | -                                                               |

## Environment vs `system_config`

Each env-mapped `system_config` row is seeded from its environment variable on first boot. After
that, precedence depends on whether the row has been changed through the admin API:

- **Until an admin changes it** (`updatedBy IS NULL`), the mapped environment variable is
  re-applied on **every** boot. This keeps env-driven config authoritative and stops a seeded
  default from permanently shadowing a later `.env` change. When a boot overwrites a stored value
  that differs, it is logged at `warn`.
- **Once an admin changes it** through the admin system-config endpoints, the row records who made
  the change (`updatedBy`) and becomes authoritative. The mapped environment variable is no longer
  consulted for that key, so the admin change survives restarts and later `.env` edits do not
  affect it.

Both the whole-config `PATCH /system-config/admin` and the per-provider `/system-config/oauth-providers`
endpoints set `updatedBy`, whether the caller authenticates with a service token or with an admin
access token. So a change made in the admin console sticks. To make a seeded value change through
env again after an admin has taken it over, clear that row's `updatedBy` (or delete the row and let
it re-seed).

Reads are cached in-process, so a `system_config` write should invalidate the cache to take
effect immediately. See [`getSystemConfig.ts`](../src/config/getSystemConfig.ts).

## See also

- [`.env.example`](../.env.example) - annotated template
- [docs/production-operations.md](./production-operations.md) - secrets inventory, key rotation
- [docs/oauth.md](./oauth.md) - OAuth provider configuration
- [docs/architecture.md](./architecture.md) - runtime shape and token model
