# Architecture

Seamless Auth API is an Express and TypeScript authentication service backed by Postgres. It provides passwordless authentication primitives, session issuance, JWKS publication, runtime system configuration, and administrative API endpoints for operators.

## Runtime Components

- Express app: global middleware, CORS, rate limits, OpenAPI metadata, and route loading.
- Routes: thin endpoint declarations with request/response schemas.
- Controllers: request handling and response shaping.
- Services: reusable auth, session, messaging, organization, OAuth, lockout, redaction, and step-up logic.
- Models: Sequelize models for users, credentials, sessions, system config, auth events, organizations, TOTP credentials, and OAuth identities.
- Postgres: source of truth for users, credentials, sessions, config, and audit records.

## Request Flow

1. Express receives a request and applies global middleware.
2. Route declarations validate params, query, and body schemas.
3. Auth middleware validates access or ephemeral tokens where required.
4. Controllers call service/model layers.
5. Response schemas validate JSON responses when configured.
6. Auth events are logged with sensitive metadata redacted.

## Token Model

Seamless Auth API uses three token states:

- Ephemeral token: short-lived pre-auth token used to continue registration or login flows.
- Access token: signed JWT for authenticated API access.
- Refresh token: opaque token stored only as a hash plus lookup fingerprint.

Access tokens are signed with configured JWKS signing keys. Refresh tokens are rotated and stored in the `sessions` table as non-raw values.

## Authentication Methods

Supported login methods are controlled by `login_methods` system config:

- `passkey`
- `magic_link`
- `email_otp`
- `phone_otp`
- `oauth`

Passkey-capable sessions can be restricted to passkey-only continuation by disabling `passkey_login_fallback_enabled`.

## System Configuration

Runtime configuration lives in the `system_config` table and is bootstrapped from environment variables when missing. Configuration includes token TTLs, allowed origins, WebAuthn relying-party settings, roles, OAuth providers, login methods, and lockout policy.

Use environment variables for raw secrets. Do not store raw secrets in `system_config`.

## Operational Boundaries

This repository contains the auth server only. It does not include billing, hosted tenant lifecycle, managed observability, managed secret storage, or the hosted control plane. Self-hosted deployments can integrate their own infrastructure for those responsibilities.
