<p align="center">
  <img src="resources/seamless-auth-logo.svg" alt="Seamless Auth key logo" width="180" />
</p>

# Seamless Auth API

![coverage](resources/coverage-badge.svg)
[![Publish Docker Image](https://github.com/fells-code/seamless-auth-api/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/fells-code/seamless-auth-api/actions/workflows/docker-publish.yml)

**Seamless Auth API** is the open-source core authentication server for SeamlessAuth: an exclusively passwordless authentication system designed for modern web applications.

It provides the backend services for passkeys (WebAuthn) and other passwordless flows, issuing secure sessions and tokens while giving teams full transparency into how authentication is implemented.

> Looking for the managed experience (hosting, upgrades, metrics, backups, SLAs)? See **https://seamlessauth.com** for managed services.

## Contents

- [Scope and non-goals](#scope-and-non-goals)
- [Why Seamless Auth API](#why-seamless-auth-api)
- [High-level architecture](#high-level-architecture)
- [Bearer token contract](#bearer-token-contract)
- [Local development quickstart](#local-development-quickstart)
- [Typed API client](#typed-api-client)
- [Capabilities and configuration](#capabilities-and-configuration)
- [Docker quickstart](#docker-quickstart)
- [Running the image yourself](#running-the-image-yourself)
- [Production guidance](#production-guidance)
- [Contributing](#contributing)
- [Public docs](#public-docs)
- [Security](#security)
- [License](#license)

## Scope and non-goals

Seamless Auth API is the **open-source authentication engine** that powers SeamlessAuth. Its goal is to provide secure, auditable, and self-hostable passwordless authentication primitives.

### What this repository includes

- Passwordless authentication flows (passkeys, OTP, and magic links where configured)
- Optional OAuth login through configured external identity providers
- Secure session and token handling
- User registration and authentication APIs
- WebAuthn / passkeys support, including PRF-capable primitives for browser-local key derivation
- JWKS and token verification endpoints
- Database models and migrations required for auth
- The self-hostable admin console, served at `/console` (see below)
- Local development and self-hosting support

Everything in this repository can be audited, modified, self-hosted, and run without any
SeamlessAuth-managed services.

### The admin console

The published Docker image bundles the [admin dashboard SPA](https://github.com/fells-code/seamless-auth-admin-dashboard)
at a pinned release and serves it from the API's own origin at `/console`. It is enabled by
default; set `SERVE_ADMIN_DASHBOARD=false` to turn it off. Serving is additive, so the `/admin/*`
API routes always keep priority. See
[docs/configuration.md](./docs/configuration.md#admin-dashboard-optional) for the variables and the
version-pinning model.

The console is a single-instance operator UI. The multi-tenant portal described below is a
different product.

### What this repository does not include

The following are **intentionally out of scope** and are part of the managed SeamlessAuth service:

- The multi-tenant control plane and hosted portal
- Billing, subscriptions, or plan enforcement
- Tenant provisioning or lifecycle management
- Hosted metrics, analytics, or usage dashboards
- Managed secrets storage or key rotation services
- Automated upgrades, backups, or restore tooling
- Managed email or SMS services. The API can send directly through configured provider adapters or
  return external-delivery payloads to a trusted server adapter, but SeamlessAuth Managed handles the
  operated delivery service.
- Support SLAs or operational monitoring

Self-hosted users are free to implement any of the above on their own, and are never required to use
the SeamlessAuth managed service.

### About secrets and infrastructure

Seamless Auth API expects secrets to be provided by the environment or by a user-supplied secret
store. This repository does **not** assume any specific cloud provider, billing system, or control
plane.

## Why Seamless Auth API

- Passwordless-first design (no passwords to steal)
- Bearer/JSON auth API with opaque refresh tokens and signed access tokens
- WebAuthn / passkeys support, with optional PRF for products that need browser-local key material
- JWKS publication for access-token verification, and separate service-token guards for trusted
  server adapters
- Built for inspection, auditability, and self-hosting

### Who this is for

- Teams that want to **self-host** authentication infrastructure
- Security-conscious organizations that require code transparency
- Developers evaluating SeamlessAuth internals before using the hosted offering

## High-level architecture

- Auth server (this repository)
- Postgres for persistence
- Your application integrates via:
  - A SeamlessAuth adapter, which bridges browser cookies to this API's bearer contract:
    [`@seamless-auth/express`](https://www.npmjs.com/package/@seamless-auth/express) for the server
    side and [`@seamless-auth/react`](https://www.npmjs.com/package/@seamless-auth/react) for the
    browser (recommended)
  - Direct HTTP APIs (advanced), see
    [docs/direct-http-quickstart.md](./docs/direct-http-quickstart.md) for an end-to-end `curl`
    login, token, and refresh walkthrough

## Bearer token contract

Seamless Auth API returns JSON tokens instead of browser auth cookies.

- Pre-auth flows return an ephemeral `token`; send it as `Authorization: Bearer <token>` to routes
  marked as ephemeral-authenticated, such as OTP, magic-link, and WebAuthn continuation routes.
- Completed login, registration, OAuth, TOTP, passkey, and refresh flows return an access `token`;
  send it as `Authorization: Bearer <token>` to access-authenticated routes.
- Refresh uses the opaque `refreshToken` value, not the access token.
- Internal service tokens remain separate. They are used only by explicitly service-token-protected
  paths or headers such as external delivery support, not as user access or ephemeral bearer tokens.
  Do not send SeamlessAuth access or ephemeral JWTs as `x-seamless-service-token`.

Full per-flow status codes and terminology live in
[docs/api-contract.md](./docs/api-contract.md).

## Local development quickstart

### Prerequisites

- Node.js 24 (the `engines` field requires `>=24 <25`; see `.nvmrc`)
- Postgres (local, Docker, or managed)

### Configuration

Copy `.env.example` to `.env` and populate values for your local environment. Never commit real
secrets.

For a full reference of every environment variable and `system_config` key, including which are
required, their defaults, and where each takes effect, see
[docs/configuration.md](./docs/configuration.md).

For a default local Postgres instance, `.env.example` expects:

```text
DB_HOST=localhost
DB_PORT=5432
DB_NAME=seamless_auth
DB_USER=myuser
DB_PASSWORD=mypassword
```

### Run locally

```bash
npm install
npm run migrate:up
npm run dev
```

The server starts on `http://localhost:5312` by default.

Verify it:

```bash
curl http://localhost:5312/health/status
```

In development, OpenAPI is available at `http://localhost:5312/openapi.json` and Swagger UI at
`http://localhost:5312/docs`. Both are disabled when `NODE_ENV=production`.

## Typed API client

The full OpenAPI document is committed at [`openapi.json`](./openapi.json), with TypeScript types
generated from it at [`src/generated/api.ts`](./src/generated/api.ts). Both are produced from the
live route definitions:

```bash
npm run generate:api
```

This package is not published to npm, so downstream projects should consume the committed
`openapi.json` and generate types into their own tree:

```bash
npx openapi-typescript https://raw.githubusercontent.com/fells-code/seamless-auth-api/main/openapi.json -o src/seamless-auth.ts
```

Those types can then be paired with a typed fetch wrapper such as `openapi-fetch`:

```ts
import type { paths } from './seamless-auth.js';

type MeResponse = paths['/users/me']['get']['responses'][200]['content']['application/json'];
```

Both committed artifacts are checked by the test suite, so a route or schema change that is not
regenerated fails CI rather than silently drifting.

## Capabilities and configuration

Each capability below is summarized here and documented in full under [`docs/`](./docs).

### Login method policy

Administrators control which methods may continue after `/login` creates a pre-authenticated
session. `LOGIN_METHODS` accepts any of `passkey`, `magic_link`, `email_otp`, `phone_otp`, or
`oauth`, and defaults to `passkey,magic_link`. Set `PASSKEY_LOGIN_FALLBACK_ENABLED=false` when
passkey-capable sessions should continue with passkeys only. When fallback is enabled, `/login`
returns `loginMethods` so clients can offer only the allowed continuations for that user and device.

See [docs/configuration.md](./docs/configuration.md).

### OAuth login

OAuth lets adopters offer login with external providers such as Google, GitHub, or Facebook, or any
provider supporting an authorization-code exchange and a userinfo endpoint. Seamless Auth still
issues the final SeamlessAuth session. Provider access tokens are used only during the callback to
fetch the profile; they are never logged, stored, or returned to clients.

Enable it by adding `oauth` to `LOGIN_METHODS` and configuring `oauth_providers` in `system_config`
or the `OAUTH_PROVIDERS` environment variable. Client secrets are referenced by environment variable
name through `clientSecretEnv` and never stored in system config. The browser flow runs through
`GET /oauth/providers`, `POST /oauth/:providerId/start`, and `POST /oauth/:providerId/callback`.

Provider JSON, redirect and PKCE policy, account-linking rules, and the full security notes are in
[docs/oauth.md](./docs/oauth.md).

### Lockout policy and rate limits

`LOCKOUT_POLICY` configures account lockout for identified users after repeated failed login
attempts, and is manageable through `system_config`. Lockout applies only after Seamless Auth has
identified the target user, so route-level rate limits remain the defense for unknown identifiers,
OTP delivery abuse, and broad IP pressure.

Beyond the configurable global limit (`RATE_LIMIT`), dedicated per-IP and per-identity limiters
guard the OTP, magic-link, registration, and OAuth routes. An automated test or conformance suite
driving many of these flows from a single IP will trip them. For those environments only,
`DISABLE_AUTH_RATE_LIMITS=true` skips every auth limiter. It is refused under `NODE_ENV=production`,
like `ALLOW_UNCREDENTIALED_DELIVERY_SECRETS`, so it can never weaken a deployed server.

See [docs/admin-operations.md](./docs/admin-operations.md#lockout-policy).

### Scoped roles

Global roles may be plain names such as `admin` or scoped names such as `admin:read` and
`admin:write`. The legacy `admin` role remains a broad administrator role and satisfies both scoped
admin checks. `admin:write` also satisfies `admin:read`; `admin:read` does not satisfy write checks.
Use `available_roles` to publish the assignable catalog and `default_roles` for new users.

See [docs/admin-operations.md](./docs/admin-operations.md#scoped-admin-roles).

### Admin-assisted device replacement

Administrators with write access can prepare an account for device replacement with
`POST /admin/users/:userId/recovery/device-replacement`. The endpoint requires a fresh step-up
session and can revoke active sessions, remove registered passkeys, and disable enabled TOTP
credentials. It returns counts only, never secrets, credential private material, TOTP secrets, or
recovery codes.

See [docs/admin-operations.md](./docs/admin-operations.md#device-replacement-recovery).

### WebAuthn PRF

SeamlessAuth can request PRF-capable passkeys and PRF assertions without ever receiving PRF output.
See [docs/webauthn-prf.md](./docs/webauthn-prf.md) for API usage, browser limitations, SDK contract
guidance, and local key-material handling rules.

### Sensitive data redaction

SeamlessAuth redacts sensitive data from logs and auth-event metadata by default. This includes
tokens, OTPs, magic-link URLs, PRF salts and outputs, OAuth codes and state, bearer credentials,
configured secrets, email and phone fields inside audit snapshots, and legacy event metadata
returned through admin endpoints.

Delivery payloads containing OTPs or magic-link tokens are returned only when callers explicitly
request external delivery with `x-seamless-auth-delivery-mode: external`. In production, external
delivery also requires a valid `x-seamless-service-token` from a trusted server adapter. This must
be an internal service token, not a SeamlessAuth access or ephemeral token.

Admin and user endpoints use explicit minimized response schemas. They do not return WebAuthn public
keys, refresh-token hashes or lookups, challenge context, verification tokens, PRF output, TOTP
secrets, or provider tokens.

See [docs/security-posture.md](./docs/security-posture.md).

## Docker quickstart

This is the fastest way to run Seamless Auth API locally. It requires only Docker.

[`docker-compose.yml`](./docker-compose.yml) brings up Postgres and the API together with
development defaults, so there is nothing to configure first: no `.env` file, no generated secrets,
no separate Postgres.

```bash
docker compose up
```

That starts the API on `http://localhost:5312`, runs migrations on first boot, generates a
development signing keypair, and serves the admin console at `http://localhost:5312/console`.

Verify it:

```bash
curl http://localhost:5312/health/status
```

To get an admin account, sign up at `/console` with `owner@example.com`. That address is the compose
file's `OWNER_EMAIL`, so the account is granted the `admin:write` and `admin` roles on creation.
Override it before first boot to use your own:

```bash
OWNER_EMAIL=you@example.com docker compose up
```

Other values worth overriding are `API_PORT`, `POSTGRES_PORT`, `APP_ORIGINS`, `ORIGINS`, and
`SEAMLESS_AUTH_IMAGE` (to pin a specific published tag). Stop the stack with `docker compose down`,
or `docker compose down -v` to also discard the database.

> The compose defaults are for local development only. They use a well-known shared secret, run with
> `NODE_ENV=development`, and return OTP codes and magic-link URLs in API responses instead of
> sending them, which is what makes the stack usable without an email or SMS transport. See
> [docs/production-operations.md](./docs/production-operations.md) before deploying.

Contributors working on the API itself should use
[`docker-compose.dev.yml`](./docker-compose.dev.yml) instead, which builds from source and
hot-reloads. See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Running the image yourself

If you already have Postgres and want to run just the API container:

```bash
docker pull ghcr.io/fells-code/seamless-auth-api:latest
```

Available tags:

- `latest`, the most recent published release
- `vX.Y.Z`, specific versioned releases

Create an environment file from the example and adjust as needed. Do not commit `.env` files; they
are ignored by default.

```bash
cp .env.example .env
```

```bash
docker run --rm \
  --env-file .env \
  -e DB_HOST=host.docker.internal \
  -p 5312:5312 \
  ghcr.io/fells-code/seamless-auth-api:latest
```

On start the container validates required environment variables, generates or loads signing keys,
**runs any pending migrations**, and then starts the server on port `5312`. Migrations are applied
on every boot, so upgrades that include them need no separate step.

Verify it is running:

```bash
curl http://localhost:5312/health/status
```

## Production guidance

Authentication infrastructure is security-sensitive. For production deployments:

- Use HTTPS end-to-end
- Keep access and refresh tokens out of browser-readable storage. This API does not set or read
  browser auth cookies; browser-facing apps should integrate through a trusted server adapter or
  backend.
- Restrict CORS origins
- Generate, rotate, and mount production signing keys through environment-backed secret management
  rather than relying on the development keypair
- Enable database backups and test restores
- Monitor authentication failures and suspicious behavior
- Treat `system_config` values as runtime configuration, not a secret store

This image contains only the open-source authentication server and its admin console. No billing or
managed infrastructure is included.

See [docs/production-operations.md](./docs/production-operations.md) for key, secret, rotation,
lockout, and deployment guidance.

### Prefer not to self-host?

SeamlessAuth managed services provide a fully managed experience built on this same open-source
core, including hosting, upgrades, backups, and SLAs.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Public docs

- [AGENTS.md](./AGENTS.md) for a fast codebase briefing aimed at coding agents and maintainers
- [docs/architecture.md](./docs/architecture.md) for runtime structure and request flow
- [docs/configuration.md](./docs/configuration.md) for the full env var and `system_config` reference
- [docs/api-contract.md](./docs/api-contract.md) for tokens, per-flow status codes, and terminology
- [docs/direct-http-quickstart.md](./docs/direct-http-quickstart.md) for a curl login/token/refresh walkthrough
- [docs/extending.md](./docs/extending.md) for message-delivery providers and extension points
- [docs/oauth.md](./docs/oauth.md) for OAuth provider setup and security behavior
- [docs/webauthn-prf.md](./docs/webauthn-prf.md) for PRF-capable passkey usage
- [docs/admin-operations.md](./docs/admin-operations.md) for scoped admin and recovery operations
- [docs/production-operations.md](./docs/production-operations.md) for production deployment guidance
- [docs/security-posture.md](./docs/security-posture.md) for deliberate security tradeoffs (enumeration, token replay, data at rest)

## Security

**Do not open public issues for security vulnerabilities.**

Email: security@seamlessauth.com  
Include reproduction steps, affected versions, and impact if known.

## License

Licensed under **GNU Affero General Public License v3.0 (AGPL-3.0-only)**.

If you want to embed Seamless Auth API into a proprietary product or offer it as a managed service
without AGPL obligations, commercial licenses may be available.

Contact: support@seamlessauth.com
