# Seamless Auth API

![coverage](resources/coverage-badge.svg)
[![Publish Docker Image](https://github.com/fells-code/seamless-auth-api/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/fells-code/seamless-auth-api/actions/workflows/docker-publish.yml)

**Seamless Auth API** is the open-source core authentication server for SeamlessAuth: an exclusively passwordless authentication system designed for modern web applications.

It provides the backend services for passkeys (WebAuthn) and other passwordless flows, issuing secure sessions and tokens while giving teams full transparency into how authentication is implemented.

> Looking for the managed experience (hosting, upgrades, dashboards, metrics, backups, SLAs)? See **https://seamlessauth.com** for managed services.

## Scope and Non-Goals

Seamless Auth API is the **open-source authentication engine** that powers SeamlessAuth. Its goal is to provide secure, auditable, and self-hostable passwordless authentication primitives.

This repository intentionally focuses on **authentication only**.

### What this repository includes

- Passwordless authentication flows (e.g. passkeys, OTP where configured)
- Optional OAuth login through configured external identity providers
- Secure session and token handling
- User registration and authentication APIs
- WebAuthn / Passkeys support
- WebAuthn PRF-capable passkey primitives for browser-local key derivation
- JWKS and token verification endpoints
- Database models and migrations required for auth
- Local development and self-hosting support

Everything in this repository can be:

- Audited
- Modified
- Self-hosted
- Run without any SeamlessAuth-managed services

### What this repository does **not** include

The following are **intentionally out of scope** and are part of the managed SeamlessAuth service:

- Admin portal or dashboard UI
- Billing, subscriptions, or plan enforcement
- Tenant provisioning or lifecycle management
- Hosted metrics, analytics, or usage dashboards
- Managed secrets storage or key rotation services
- Automated upgrades, backups, or restore tooling
- Email or SMS services to service the OTP requests
- Support SLAs or operational monitoring

Self-hosted users are free to implement any of the above on their own, but they are not required to use SeamlessAuth Managed Service.

### About secrets and infrastructure

Seamless Auth API expects secrets to be provided by the environment or by a user-supplied secret store.

This repository does **not** assume any specific cloud provider, billing system, or control plane.

## Why Seamless Auth API

- Passwordless-first design (no passwords to steal)
- Bearer/JSON auth API with opaque refresh tokens and signed access tokens
- WebAuthn / passkeys support
- Optional WebAuthn PRF support for products that need browser-local key material
- Token and JWKS support for service-to-service auth
- Built for inspection, auditability, and self-hosting

This repository contains **only the auth server**. The admin portal, billing system, and hosted control plane are proprietary and offered as a managed service.

## Who this is for

- Teams that want to **self-host** authentication infrastructure
- Security-conscious organizations that require code transparency
- Developers evaluating SeamlessAuth internals before using the hosted offering

If you want hosted auth with a full control plane and operational support, use the managed service instead.

## High-level architecture

- Auth server (this repository)
- Postgres for persistence
- Your application integrates via:
  - SeamlessAuth server SDK (recommended)
  - Direct HTTP APIs (advanced)

---

## Local development quickstart

### Prerequisites

- Node.js (LTS recommended)
- Postgres (local, Docker, or managed)

### Configuration

Copy the `.env.example` to an `.env` file and populate empty values.

Never commit real secrets. Use `.env.example` for documentation.

### WebAuthn PRF

SeamlessAuth can request PRF-capable passkeys and PRF assertions without ever receiving PRF output.
See [docs/webauthn-prf.md](./docs/webauthn-prf.md) for API usage, browser limitations, SDK
contract guidance, and local key-material handling rules.

### Login Method Policy

Administrators can control which methods may continue after `/login` creates a pre-authenticated
session. Configure `LOGIN_METHODS` with any of `passkey`, `magic_link`, `email_otp`, `phone_otp`,
or `oauth`. The default is `passkey,magic_link`.

Set `PASSKEY_LOGIN_FALLBACK_ENABLED=false` when passkey-capable sessions should continue with
passkeys only. When fallback is enabled, `/login` returns `loginMethods` so clients can show only
the allowed continuations for that user and device.

### OAuth Login

OAuth support lets adopters offer login with external providers such as Google, GitHub, Facebook,
or any compatible provider that supports an authorization-code exchange and a userinfo endpoint.
Seamless Auth still issues the final SeamlessAuth session. Provider access tokens are used only
during the callback to fetch the profile; they are not logged, stored, returned to clients, or
included in API responses.

Enable OAuth by adding `oauth` to `LOGIN_METHODS` and configuring `oauth_providers` in
`system_config` or the `OAUTH_PROVIDERS` environment variable. `OAUTH_PROVIDERS` is JSON. Secrets
are referenced by environment variable name through `clientSecretEnv`; do not put client secrets in
system config.

```json
[
  {
    "id": "google",
    "name": "Google",
    "enabled": true,
    "clientId": "google-oauth-client-id",
    "clientSecretEnv": "GOOGLE_CLIENT_SECRET",
    "authorizationUrl": "https://accounts.google.com/o/oauth2/v2/auth",
    "tokenUrl": "https://oauth2.googleapis.com/token",
    "userInfoUrl": "https://openidconnect.googleapis.com/v1/userinfo",
    "scopes": ["openid", "email", "profile"],
    "redirectUri": "https://app.example.com/oauth/callback",
    "redirectUris": ["https://app.example.com/oauth/callback"],
    "subjectJsonPath": "sub",
    "emailJsonPath": "email",
    "emailVerifiedJsonPath": "email_verified",
    "nameJsonPath": "name",
    "allowSignup": true,
    "accountLinking": "email",
    "requireEmailVerified": true
  }
]
```

The browser/client flow is:

1. `GET /oauth/providers` returns enabled public provider metadata.
2. `POST /oauth/:providerId/start` returns a signed `state` and provider `authorizationUrl`.
3. The browser redirects to `authorizationUrl`.
4. The provider redirects back to your `redirectUri` with `code` and `state`.
5. The client posts `{ code, state }` to `POST /oauth/:providerId/callback`.
6. Seamless Auth validates state, exchanges the code, fetches userinfo, links or creates the local
   user, and issues the normal SeamlessAuth access/refresh JSON payload.

Example direct API start request:

```bash
curl -X POST http://localhost:5312/oauth/google/start \
  -H 'Content-Type: application/json' \
  -d '{
    "redirectUri": "http://localhost:5173/oauth/callback",
    "returnTo": "http://localhost:5173/dashboard"
  }'
```

Example callback request after the provider redirects back:

```bash
curl -X POST http://localhost:5312/oauth/google/callback \
  -H 'Content-Type: application/json' \
  -d '{
    "code": "provider-authorization-code",
    "state": "signed-state-from-start"
  }'
```

Security notes:

- OAuth `state` is signed and expires after a short window.
- `redirectUri` must exactly match a provider `redirectUris` entry when configured. Providers
  without a redirect allowlist fall back to trusted configured origins.
- `returnTo` must match configured `origins`.
- OIDC providers that request the `openid` scope receive a nonce bound into the signed state.
- Provider access tokens are never persisted.
- OAuth identities are stored as provider id + provider subject in `oauth_identities`.
- Existing users are linked by email only when `accountLinking` is `email`; set
  `accountLinking: "disabled"` to require an existing provider identity.
- New users are created only when `allowSignup` is enabled for that provider.
- Set `requireEmailVerified: true` for providers that expose a reliable email verification claim.

### Lockout Policy

`LOCKOUT_POLICY` configures account lockout for identified users after repeated failed login
attempts. The value is JSON and is also manageable through `system_config`:

```json
{
  "enabled": true,
  "maxFailures": 10,
  "windowSeconds": 900,
  "lockoutSeconds": 900
}
```

Lockout is checked after Seamless Auth has identified the target user. Keep route-level rate limits
enabled for unknown identifiers, OTP delivery abuse, and broad IP pressure.

### Admin-Assisted Device Replacement

Administrators with write access can prepare an account for device replacement with:

```http
POST /admin/users/:userId/recovery/device-replacement
```

The endpoint requires a fresh step-up session and can revoke active sessions, remove registered
passkeys, and disable enabled TOTP credentials. It returns counts only; it never returns secrets,
credential private material, TOTP secrets, or recovery codes.

### Sensitive Data Redaction

SeamlessAuth redacts sensitive data from logs and auth-event metadata by default. This includes
tokens, OTPs, magic-link URLs, PRF salts and outputs, OAuth codes/state, bearer credentials,
configured secrets, email/phone fields inside audit snapshots, and legacy event metadata returned
through admin endpoints.

Delivery payloads that contain OTPs or magic-link/bootstrap tokens are returned only when callers
explicitly request external delivery with `x-seamless-auth-delivery-mode: external`. In production,
external delivery also requires a valid `x-seamless-service-token` from a trusted server adapter.
Development-only bootstrap token details require `x-seamless-auth-include-sensitive: true` and are
never enabled in production.

### Scoped Roles

Global roles may be plain names such as `admin` or scoped names such as `admin:read` and
`admin:write`. The legacy `admin` role remains a broad administrator role and grants both scoped
admin checks. `admin:write` also satisfies `admin:read`; `admin:read` does not satisfy write checks.

Use `available_roles` to publish the assignable role catalog and `default_roles` for new users.
Role names may contain letters, numbers, and hyphens, with optional colon-separated scope segments.
Whitespace, underscores, slashes, and backslashes are rejected.

Admin routes are split by intent:

- read routes accept `admin`, `admin:read`, or `admin:write`
- write routes accept `admin` or `admin:write`
- plain `admin` checks remain exact for backwards compatibility

### Install & run

```
npm install
npm run dev
```

The server should start on `http://localhost:5312` (or your configured port).

---

# Docker Quickstart (5 minutes)

This is the fastest way to run **Seamless Auth API** locally using Docker.

---

## Prerequisites

- Docker (Docker Desktop or Docker Engine)
- A running PostgreSQL instance (local or Docker)

---

## 1. Pull the public image

```bash
docker pull ghcr.io/fells-code/seamless-auth-api:latest
```

Available tags:

- `latest` – latest stable release
- `nightly` – latest build from `main`
- `vX.Y.Z` – specific versioned releases

---

## 2. Create an environment file

Copy the example and adjust as needed:

```bash
cp .env.example .env
```

⚠️ Do not commit `.env` files. They are ignored by default.

---

## 3. Run PostgreSQL (example with Docker)

If you do not already have Postgres running:

```bash
docker run -d \
  --name seamless-auth-postgres \
  -e POSTGRES_USER=myuser \
  -e POSTGRES_PASSWORD=mypassword \
  -e POSTGRES_DB=seamless_auth \
  -p 5432:5432 \
  postgres:16
```

Update DB env values accordingly.

## 4. Run Seamless Auth Server

```bash
docker run --rm \
  --env-file .env \
  -p 5312:5312 \
  ghcr.io/fells-code/seamless-auth-api:latest
```

The server will:

- Validate required environment variables
- Start on port `5312`
- Expose health and authentication endpoints

## 5. Verify it is running

```bash
curl http://localhost:5312/health
```

You should receive a healthy response.

## Notes for self-hosting

- Secrets are provided via environment variables
- Keys are generated or mounted at runtime as needed
- This image contains only the open-source authentication server
- No admin portal, billing, or managed infrastructure is included

For production deployments:

- Use HTTPS
- Use a trusted server adapter or backend when exposing auth flows to browsers
- Rotate signing keys
- Back up your database
- Monitor authentication failures

See [docs/production-operations.md](./docs/production-operations.md) for key, secret, rotation,
lockout, and deployment guidance.

## Prefer not to self-host?

SeamlessAuth managed services provides a fully managed experience built on top of this same open-source core, including hosting, upgrades, dashboards, backups, and SLAs.

## Production notes

Authentication infrastructure is security-sensitive.

For production deployments:

- Use HTTPS end-to-end
- Keep access and refresh tokens out of browser-readable storage
- Restrict CORS origins
- Rotate signing keys and secrets regularly
- Enable database backups and test restores
- Monitor auth failures and suspicious behavior

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Public Docs

- [AGENTS.md](./AGENTS.md) for a fast codebase briefing aimed at coding agents and maintainers
- [docs/architecture.md](./docs/architecture.md) for runtime structure and request flow
- [docs/oauth.md](./docs/oauth.md) for OAuth provider setup and security behavior
- [docs/webauthn-prf.md](./docs/webauthn-prf.md) for PRF-capable passkey usage
- [docs/admin-operations.md](./docs/admin-operations.md) for scoped admin and recovery operations
- [docs/production-operations.md](./docs/production-operations.md) for production deployment guidance

## Security

**Do not open public issues for security vulnerabilities.**

Email: security@seamlessauth.com  
Include reproduction steps, affected versions, and impact if known.

## License

Licensed under **GNU Affero General Public License v3.0 (AGPL-3.0-only)**.

If you want to embed Seamless Auth Server into a proprietary product or offer it as a managed service without AGPL obligations, commercial licenses may be available.

Contact: support@seamlessauth.com
