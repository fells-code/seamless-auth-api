# Configuration Reference

This is the single source of truth for how Seamless Auth API is configured. It lists every
environment variable, whether it is required, its default, and where it takes effect.

There are two configuration layers:

- **Environment variables** boot the process, connect external systems (database, messaging,
  signing keys), and seed the runtime config on first start.
- **`system_config` table** holds runtime settings (token TTLs, roles, origins, login methods,
  OAuth providers, rate limits). These are seeded from environment variables on first boot and
  are the source of truth afterwards.

> Because `system_config` is seeded once, editing an already-seeded value in `.env` does not
> change running behavior. See [Environment vs system_config](#environment-vs-system_config).

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
| `REFRESH_TOKEN_TTL`   | `1h`                    | Refresh token lifetime (`\d+[smhd]`)              |
| `RATE_LIMIT`          | `100`                   | Global request rate limit                         |
| `DELAY_AFTER`         | `50`                    | Requests before slow-down kicks in                |
| `RPID`                | `localhost`             | WebAuthn relying party ID                         |
| `ORIGINS`             | `http://localhost:5173` | WebAuthn allowed origins (comma-separated)        |
| `API_SERVICE_TOKEN`   | `<32-byte hex>`         | Trusted server-adapter and internal bearer secret |
| Database connectivity | see below               | `DATABASE_URL` **or** the `DB_*` set              |

Everything else is optional or environment-specific.

The container entrypoint validates these at startup via
[`validateEnvs.sh`](../validateEnvs.sh) and exits with a clear message if one is missing.

## Environment variables

Legend: **Required** = process refuses to boot without it (enforced by `validateEnvs.sh` in the
container path). **Seeds `system_config`** = value is copied into the runtime config table on
first boot.

### Application

| Variable          | Required | Default       | Seeds `system_config` | Notes                                                                                       |
| ----------------- | -------- | ------------- | --------------------- | ------------------------------------------------------------------------------------------- |
| `NODE_ENV`        | No       | `development` | No                    | `production` enables stricter checks (JWKS, secrets).                                       |
| `HOST`            | No       | `0.0.0.0`     | No                    | Bind address.                                                                               |
| `PORT`            | No       | `5312`        | No                    | Listen port.                                                                                |
| `APP_NAME`        | Yes      | -             | `app_name`            | Min 3 characters.                                                                           |
| `APP_ID`          | Yes      | -             | No                    | Stable app identifier.                                                                      |
| `APP_ORIGINS`     | Yes      | -             | No                    | CORS allowlist for callers of this API (comma-separated). Distinct from WebAuthn `ORIGINS`. |
| `ISSUER`          | Yes      | -             | No                    | JWT `iss` and issuer URL.                                                                   |
| `DEFAULT_ROLES`   | Yes      | -             | `default_roles`       | Roles for new users (comma-separated).                                                      |
| `AVAILABLE_ROLES` | Yes      | -             | `available_roles`     | Roles permitted in the system (comma-separated).                                            |

### Auth and tokens

| Variable                         | Required | Default                                                                      | Seeds `system_config`            | Notes                                                                   |
| -------------------------------- | -------- | ---------------------------------------------------------------------------- | -------------------------------- | ----------------------------------------------------------------------- |
| `ACCESS_TOKEN_TTL`               | Yes      | -                                                                            | `access_token_ttl`               | Format `\d+[smhd]`, e.g. `30m`.                                         |
| `REFRESH_TOKEN_TTL`              | Yes      | -                                                                            | `refresh_token_ttl`              | Format `\d+[smhd]`, e.g. `1h`.                                          |
| `RATE_LIMIT`                     | Yes      | -                                                                            | `rate_limit`                     | Global limit, positive integer.                                         |
| `DELAY_AFTER`                    | Yes      | -                                                                            | `delay_after`                    | Slow-down threshold, non-negative integer.                              |
| `LOGIN_METHODS`                  | No       | `passkey,magic_link`                                                         | `login_methods`                  | Any of `passkey,magic_link,email_otp,phone_otp,oauth`.                  |
| `PASSKEY_LOGIN_FALLBACK_ENABLED` | No       | `true`                                                                       | `passkey_login_fallback_enabled` | When `false`, passkey-capable sessions continue with passkey only.      |
| `LOCKOUT_POLICY`                 | No       | `{"enabled":true,"maxFailures":10,"windowSeconds":900,"lockoutSeconds":900}` | `lockout_policy`                 | JSON. Set `enabled:false` only when an upstream policy handles lockout. |

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

Provide **either** `DATABASE_URL` **or** the discrete `DB_*` variables. `DATABASE_URL` wins when
set and is preferred in containers and hosted environments.

| Variable       | Required    | Default         | Notes                                                                         |
| -------------- | ----------- | --------------- | ----------------------------------------------------------------------------- |
| `DATABASE_URL` | Conditional | -               | Full Postgres connection string. If set, the `DB_*` host set is not required. |
| `DB_HOST`      | Conditional | `localhost`     | Required when `DATABASE_URL` is unset.                                        |
| `DB_PORT`      | Conditional | `5432`          | Required when `DATABASE_URL` is unset.                                        |
| `DB_NAME`      | Conditional | `seamless_auth` | Required when `DATABASE_URL` is unset.                                        |
| `DB_USER`      | Conditional | -               | Required when `DATABASE_URL` is unset.                                        |
| `DB_PASSWORD`  | No          | -               | Password for `DB_USER`.                                                       |
| `DB_LOGGING`   | Yes         | `false`         | Logs SQL from the app and startup migrations.                                 |

### WebAuthn

| Variable  | Required | Default | Seeds `system_config` | Notes                                                                         |
| --------- | -------- | ------- | --------------------- | ----------------------------------------------------------------------------- |
| `RPID`    | Yes      | -       | `rpid`                | Relying party ID (a domain, no scheme).                                       |
| `ORIGINS` | Yes      | -       | `origins`             | WebAuthn allowed origins (comma-separated URLs). Distinct from `APP_ORIGINS`. |

### OAuth

| Variable          | Required | Default | Seeds `system_config` | Notes                                                                                                                                                                                             |
| ----------------- | -------- | ------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `OAUTH_PROVIDERS` | No       | `[]`    | `oauth_providers`     | JSON array of provider configs. Provider client secrets stay in env vars referenced by each provider's `clientSecretEnv`, never in this JSON or `system_config`. See [docs/oauth.md](./oauth.md). |

### Admin bootstrap

| Variable                      | Required      | Default | Notes                                                                            |
| ----------------------------- | ------------- | ------- | -------------------------------------------------------------------------------- |
| `SEAMLESS_BOOTSTRAP_ENABLED`  | No            | `false` | Enables the first-admin bootstrap invite flow.                                   |
| `SEAMLESS_BOOTSTRAP_SECRET`   | Conditional   | -       | Required when `SEAMLESS_BOOTSTRAP_ENABLED=true`.                                 |
| `SEAMLESS_AUTH_DEBUG_SECRETS` | No (dev only) | `false` | Logs bootstrap invite links for local debugging. **Never enable in production.** |

### Admin dashboard (optional)

This API can serve the admin dashboard SPA ([`seamless-auth-admin-dashboard`](https://github.com/fells-code/seamless-auth-admin-dashboard))
at the `/admin` subpath on its own origin (same origin as the API), so a managed instance ships
its dashboard without a separate host. Serving is additive: the admin API routes are registered
first and keep priority, and the SPA history fallback only handles unmatched `/admin/*` GETs. No
CORS changes are needed because the dashboard is same-origin with the API.

| Variable                | Required | Default             | Notes                                                                                                           |
| ----------------------- | -------- | ------------------- | --------------------------------------------------------------------------------------------------------------- |
| `SERVE_ADMIN_DASHBOARD` | No       | `true`              | Serve the SPA at `/admin`. Set to `false` to disable. When enabled but no build is bundled, serving is skipped. |
| `ADMIN_DASHBOARD_DIR`   | No       | `./admin-dashboard` | Directory of the built SPA, relative to the compiled bundle. The Docker image copies the dashboard build here.  |

**Reserved paths.** The dashboard shares the `/admin` namespace with the admin API. These
sub-paths always resolve to the API, so the dashboard's client routes must avoid them (a hard
refresh on one hits the API, not the SPA): `/admin/organizations`, `/admin/users`,
`/admin/sessions`, `/admin/audit-events`, `/admin/credential-count`.

**Build integration and version bumps.** The dashboard package is private (not on npm), so the
Docker image fetches it from git at a pinned ref and builds the `/admin` variant in a dedicated
stage (see the `admin-dashboard` stage in [`Dockerfile`](../Dockerfile)). Bump the dashboard
shipped to tenants by raising the `SEAMLESS_ADMIN_DASHBOARD_REF` build ARG (a git tag); the new
version then flows to tenants through the normal upstream auth-image release. The dedicated
same-origin dashboard build (origin-derived API base) is a coordinated dashboard PR; until it
merges, point `SEAMLESS_ADMIN_DASHBOARD_REF` at that PR's branch. See [seamless-iac#37](https://github.com/fells-code/seamless-iac/issues/37).

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

`system_config` is seeded **once**. After first boot, the row is authoritative and the mapped
environment variable is no longer consulted for that key. To change a seeded value you must update
the `system_config` row (via the admin system-config endpoints), not just `.env`.

Reads are cached in-process, so a `system_config` write should invalidate the cache to take
effect immediately. See [`getSystemConfig.ts`](../src/config/getSystemConfig.ts).

## See also

- [`.env.example`](../.env.example) - annotated template
- [docs/production-operations.md](./production-operations.md) - secrets inventory, key rotation
- [docs/oauth.md](./oauth.md) - OAuth provider configuration
- [docs/architecture.md](./architecture.md) - runtime shape and token model
