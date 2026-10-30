# Architecture

Seamless Auth API is an Express and TypeScript authentication service backed by Postgres. It provides passwordless authentication primitives, session issuance, JWKS publication, runtime system configuration, and administrative API endpoints for operators.

## Runtime Components

- Express app: global middleware, CORS, rate limits, OpenAPI metadata, and route loading.
- Routes: thin endpoint declarations with request and response schemas.
- Controllers: request handling and response shaping.
- Services: reusable auth, session, messaging, organization, OAuth, lockout, redaction, and step-up logic.
- Models: Sequelize models for users, credentials, sessions, system config, auth events, organizations, TOTP credentials, and OAuth identities.
- Postgres: source of truth for users, credentials, sessions, config, and audit records.

## Deployment Topology

This API is one component in a small system. It speaks a single Bearer/JSON contract and never
sets or reads browser cookies. Browser apps do not call it directly in the recommended setup;
a trusted server adapter sits in between.

```mermaid
flowchart LR
  browser["Browser<br/>(@seamless-auth/react)"]
  adapter["Trusted server adapter<br/>(@seamless-auth/express / core)"]
  api["This API<br/>(seamless-auth-api)"]
  db[("Postgres")]

  browser -- "cookies<br/>credentials: include" --> adapter
  adapter -- "Bearer + service token<br/>JSON, no cookies" --> api
  adapter -- "JWKS verify<br/>/.well-known/jwks.json" --> api
  api --> db
```

**Trusted server adapter.** A server-side component (not the browser) that holds token custody
and bridges the two auth styles. In the SeamlessAuth ecosystem this is
`@seamless-auth/express` / `@seamless-auth/core`, but any backend you control can play the role.
It is "trusted" because it runs in your infrastructure, holds the session cookies
(`seamless-access`, `seamless-refresh`, `seamless-ephemeral`) on the browser side, and is the
only party that presents this API's service token. Its responsibilities:

- Terminate the browser's cookie-based session and translate it into an `Authorization: Bearer`
  header for this API.
- Attach the service token (`x-seamless-service-token`), forwarded client IP
  (`x-seamless-client-ip`) and forwarded browser user agent (`x-seamless-client-user-agent`)
  on calls that require them. Without the last, every audit row records the adapter's own
  user agent and the device class telemetry reads `unknown` (see
  [telemetry.md](./telemetry.md)).
- Verify access-token signatures against this API's JWKS (`/.well-known/jwks.json`, RS256).

Direct browser-to-API integration is possible (see the "Direct HTTP APIs (advanced)" path in the
README) but unsupported for cookie-based browser sessions, because this API issues tokens only in
JSON bodies and expects the caller to hold them securely. Keeping token custody in the adapter is
the recommended path.

### OpenID Provider service

Apps that speak OpenID Connect sign users in through a separate public service,
[seamless-auth-oidc-provider](https://github.com/fells-code/seamless-auth-oidc-provider) (the
"login edge"), not through this API. The design is [ADR 0001](./adr/0001-openid-provider.md).

```mermaid
flowchart LR
  rp["Any OIDC app"]
  edge["OpenID Provider service<br/>(public: OIDC endpoints, hosted pages, cookies)"]
  api["This API<br/>(private, no cookies)"]

  rp --> edge
  edge -- "first-party sign-in<br/>Bearer + service token" --> api
  edge -- "/oidc/* provider storage and signing<br/>service token only" --> api
```

- The edge signs users in through the same first-party routes every adapter uses, so a provider
  sign-in is an ordinary `sessions` row with every first-party protection applied.
- Its `oidc-provider` storage lives here, in `oidc_payloads`, reached through
  `/oidc/payloads/*`. A record tied to a session that is no longer live reads as absent, so any
  revocation ends provider access at once.
- Provider signing keys (`OIDC_JWKS_*`) stay here. `POST /oidc/sign` signs only for a user with a
  live session, with the `acr`, `amr` and `auth_time` that session earned, for an audience the
  client may use, and only with the active key.
- `/oidc/*` answers only the internal service token, and answers 404 while
  `oidc_provider_enabled` is off. These routes are not the public OIDC endpoints.

Provider tokens carry `iss` equal to `oidc_issuer`, never `ISSUER`, and are signed with provider
keys, so the first-party verifier rejects them.

For the full dependency and contract-coupling map across sibling repositories, see
[ecosystem.md](./ecosystem.md).

## Request Flow

1. Express receives a request and applies global middleware.
2. Route declarations validate params, query, and body schemas.
3. Auth middleware validates access or ephemeral tokens where required.
4. Controllers call service/model layers.
5. Response schemas validate JSON responses and strip undocumented fields from successful payloads.
6. Auth events are logged with sensitive metadata redacted.

## Token Model

Seamless Auth API uses three token states:

- Ephemeral token: short-lived pre-auth token used to continue registration or login flows.
- Access token: signed JWT for authenticated API access.
- Refresh token: opaque token stored only as a hash plus lookup fingerprint.

Access tokens are signed with configured JWKS signing keys. Refresh tokens are rotated and stored in the `sessions` table as non-raw values.

Routes that declare access or ephemeral auth validate SeamlessAuth-issued bearer JWTs. Internal
service tokens are intentionally separate and are accepted only by service-token-specific middleware
or headers.

The API does not set or read browser auth cookies. Browser-facing applications should keep token
custody in a trusted server adapter or backend and forward bearer tokens to the API from that trusted
layer.

## Authentication Methods

Supported login methods are controlled by `login_methods` system config:

- `passkey`
- `magic_link`
- `email_otp`
- `phone_otp`
- `oauth`

Email OTP is also how registration proves an address, so `/otp/generate-email-otp` and
`/otp/verify-email-otp` serve an unverified account whatever `login_methods` says. For an account
that is already verified those two endpoints are a sign-in, and they answer
`403 login_method_disabled` unless `email_otp` is listed (and the passkey rules below allow it).

Accounts holding a passkey can be restricted to passkey-only continuation by disabling
`passkey_login_fallback_enabled`. `phishing_resistant_only` goes further and restricts every
account to passkeys, apart from the one session that verifies a new account's address. Both
are enforced on each continuation endpoint, including the OAuth callback, as well as in the
`/login` method list. Session issuance applies both rules again as a backstop, refusing a
non-passkey factor whenever either one requires a passkey, so a sign-in path that forgets the
check fails closed instead of issuing a session. The client sends a `passkeyAvailable` capability hint on
`POST /login`, but it is advisory: it can remove passkey from a set the policy already permits,
never add a weaker method to a passkey-only one.

## System Configuration

Runtime configuration lives in the `system_config` table and is bootstrapped from environment variables when missing. Configuration includes token TTLs, allowed origins, WebAuthn relying-party settings, roles, OAuth providers, login methods, and lockout policy.

Use environment variables for raw secrets. Do not store raw secrets in `system_config`.

## OpenAPI and Response Contracts

Route modules use the `schemas` option so request validation, runtime response validation, and
OpenAPI generation stay aligned. Every route should declare an explicit response schema. Admin/user
responses are intentionally minimized and should return only fields the route contract names.

## Logging and Redaction

All log output passes through a central redaction step (`src/utils/redaction.ts`) before it is
written. Log messages are scrubbed for tokens, OTPs, magic-link URLs, bootstrap tokens, emails,
phone numbers, and known sensitive query parameters; structured metadata is redacted by key name.
This means route logs and auth events do not leak secrets even when a URL or payload contains them.
Treat redaction as a hard requirement: new sensitive fields should be added to the redaction
patterns. See [production-operations.md](./production-operations.md) for the operator-facing detail.

## Operational Boundaries

This repository contains the auth server only. It does not include billing, hosted tenant lifecycle, managed observability, managed secret storage, or the hosted control plane. Self-hosted deployments can integrate their own infrastructure for those responsibilities.
