# Seamless Auth API Architecture

This document is the deeper companion to [AGENTS.md](/Users/brandoncorbett/git/seamless-auth-api/AGENTS.md). It explains how the service boots, how authentication flows move through the codebase, and which pieces tend to matter during maintenance.

## 1. Boot Sequence

Request handling is assembled in this order:

1. [src/server.ts](/Users/brandoncorbett/git/seamless-auth-api/src/server.ts)
2. [src/models/index.ts](/Users/brandoncorbett/git/seamless-auth-api/src/models/index.ts)
3. [src/db.ts](/Users/brandoncorbett/git/seamless-auth-api/src/db.ts)
4. [src/config/bootstrapSystemConfig.ts](/Users/brandoncorbett/git/seamless-auth-api/src/config/bootstrapSystemConfig.ts)
5. [src/app.ts](/Users/brandoncorbett/git/seamless-auth-api/src/app.ts)
6. [src/lib/loadRoutes.ts](/Users/brandoncorbett/git/seamless-auth-api/src/lib/loadRoutes.ts)

Important implications:

- Models must initialize before route handlers run.
- The process will fail fast on missing database or required system configuration.
- Route registration is file-system driven, so every `*.routes.ts` file in `src/routes` is mounted automatically.

## 2. Request Pipeline

Global behavior is configured in [src/app.ts](/Users/brandoncorbett/git/seamless-auth-api/src/app.ts):

- `helmet`
- JSON body parsing
- CORS
- cookie parsing
- request logging
- rate limiting and slow-down outside test mode
- development-only OpenAPI and Swagger UI
- generic error and 404 handlers

Route modules use [src/lib/createRouter.ts](/Users/brandoncorbett/git/seamless-auth-api/src/lib/createRouter.ts) and [src/lib/defineRoute.ts](/Users/brandoncorbett/git/seamless-auth-api/src/lib/defineRoute.ts). `defineRoute` is more than syntactic sugar:

- parses params/query/body with Zod
- registers OpenAPI metadata
- can validate JSON responses against Zod schemas
- optionally attaches auth middleware through the `auth` property

If request parsing or OpenAPI output looks wrong, inspect the route definition before the controller.

## 3. Main Auth Flows

### Registration

Primary files:

- [src/routes/registration.routes.ts](/Users/brandoncorbett/git/seamless-auth-api/src/routes/registration.routes.ts)
- [src/controllers/registration.ts](/Users/brandoncorbett/git/seamless-auth-api/src/controllers/registration.ts)

Behavior:

- validates email/phone
- finds or creates the user
- issues an ephemeral token
- optionally sends or returns phone OTP delivery info
- stores bootstrap token in a cookie when present

Registration does not itself create the long-lived session. It prepares the user for OTP, magic link, or WebAuthn completion.

### OTP

Primary files:

- [src/routes/otp.routes.ts](/Users/brandoncorbett/git/seamless-auth-api/src/routes/otp.routes.ts)
- [src/controllers/otp.ts](/Users/brandoncorbett/git/seamless-auth-api/src/controllers/otp.ts)
- [src/utils/otp.ts](/Users/brandoncorbett/git/seamless-auth-api/src/utils/otp.ts)

Behavior:

- requires ephemeral auth for generation and verification endpoints
- supports both registration verification and login verification
- can either send messages directly or return delivery payloads to an external caller

### Magic Link

Primary files:

- [src/routes/magicLink.routes.ts](/Users/brandoncorbett/git/seamless-auth-api/src/routes/magicLink.routes.ts)
- [src/controllers/magicLinks.ts](/Users/brandoncorbett/git/seamless-auth-api/src/controllers/magicLinks.ts)

Behavior:

- requires ephemeral auth to request the link
- stores hashed token plus device fingerprint data
- verification endpoint marks the token used
- polling endpoint finalizes the login/session if the same device later confirms it

### WebAuthn / Passkeys

Primary files:

- [src/routes/webauthn.routes.ts](/Users/brandoncorbett/git/seamless-auth-api/src/routes/webauthn.routes.ts)
- [src/controllers/webauthn.ts](/Users/brandoncorbett/git/seamless-auth-api/src/controllers/webauthn.ts)

Behavior:

- start endpoints generate registration/authentication challenges
- finish endpoints verify browser responses with `@simplewebauthn/server`
- successful completion issues a real session
- registration/login completion can also trigger bootstrap admin promotion

### Session Management

Primary files:

- [src/services/sessionIssuance.ts](/Users/brandoncorbett/git/seamless-auth-api/src/services/sessionIssuance.ts)
- [src/services/sessionService.ts](/Users/brandoncorbett/git/seamless-auth-api/src/services/sessionService.ts)
- [src/controllers/authentication.ts](/Users/brandoncorbett/git/seamless-auth-api/src/controllers/authentication.ts)
- [src/controllers/sessions.ts](/Users/brandoncorbett/git/seamless-auth-api/src/controllers/sessions.ts)

Key concepts:

- refresh tokens are opaque random values stored only as bcrypt hashes
- access tokens are signed JWTs using the JWKS-managed signing key
- cookie auth can silently refresh sessions
- session reuse detection revokes the replacement chain

When debugging auth bugs, inspect both the token code and the `sessions` table behavior. The middleware validates both JWT claims and backing session state.

## 4. Auth Modes

`AUTH_MODE` changes the public contract of several endpoints.

### `web`

- tokens are primarily communicated via cookies
- cookie middleware is the normal auth path
- session issuance writes `seamless_access`, `seamless_refresh`, and `seamless_ephemeral`

### `server`

- more endpoints return token material in JSON
- bearer validation is used more heavily
- refresh endpoints expect bearer credentials rather than browser cookies

When modifying a controller that returns auth state, verify both branches. Many regressions in this codebase would only show up in one mode.

## 5. Config And Secrets

### Environment variables

The process relies on `.env` or runtime env vars for:

- database connection
- issuer/origin metadata
- bootstrap toggles
- service token secrets
- production signing/JWKS material
- optional direct messaging provider credentials

Reference points:

- [.env.example](/Users/brandoncorbett/git/seamless-auth-api/.env.example)
- [validateEnvs.sh](/Users/brandoncorbett/git/seamless-auth-api/validateEnvs.sh)

### `system_config`

Bootstrapped runtime values include:

- `app_name`
- `default_roles`
- `available_roles`
- token TTLs
- rate limiting config
- WebAuthn RP ID
- allowed origins

Reference points:

- [src/config/systemConfig.envMap.ts](/Users/brandoncorbett/git/seamless-auth-api/src/config/systemConfig.envMap.ts)
- [src/schemas/systemConfig.schema.ts](/Users/brandoncorbett/git/seamless-auth-api/src/schemas/systemConfig.schema.ts)
- [src/controllers/systemConfig.ts](/Users/brandoncorbett/git/seamless-auth-api/src/controllers/systemConfig.ts)

The cache in `getSystemConfig()` is process-local. Any write path should invalidate it.

## 6. Messaging

Direct delivery lives in:

- [src/services/messagingService.ts](/Users/brandoncorbett/git/seamless-auth-api/src/services/messagingService.ts)
- [src/config/directMessaging.ts](/Users/brandoncorbett/git/seamless-auth-api/src/config/directMessaging.ts)

Supported direct transports:

- AWS email
- AWS SMS
- Twilio SMS

Flows can opt out of direct sending and instead return delivery payloads by sending `x-seamless-auth-delivery-mode: external`.

This split is important when writing tests or integrating with an upstream orchestration service.

## 7. Data Model Highlights

Useful tables/models to understand early:

- `users`
- `credentials`
- `sessions`
- `auth_events`
- `magic_links`
- `system_config`
- `bootstrap_invites`

Model definitions live in [src/models](/Users/brandoncorbett/git/seamless-auth-api/src/models). Migrations live in [src/migrations](/Users/brandoncorbett/git/seamless-auth-api/src/migrations).

## 8. Testing Strategy

The test suite uses Vitest with:

- unit tests for utilities, middleware, services, config, and OpenAPI generation
- integration tests for route/controller behavior
- e2e and smoke tests for higher-level flow coverage

Reference points:

- [vitest.config.ts](/Users/brandoncorbett/git/seamless-auth-api/vitest.config.ts)
- [tests/setup/env.ts](/Users/brandoncorbett/git/seamless-auth-api/tests/setup/env.ts)
- [tests/setup/globalSetup.ts](/Users/brandoncorbett/git/seamless-auth-api/tests/setup/globalSetup.ts)

Practical guidance:

- use unit tests for small auth helper changes
- use integration tests when touching controllers or middleware
- update OpenAPI tests if you change route schemas or docs generation

## 9. Maintenance Notes And Sharp Edges

- Some routes declare auth through `middleware: [attachAuthMiddleware(...)]` instead of the `auth` field. That works at runtime, but OpenAPI security metadata is only added by the `auth` field today.
- `defineRoute` expects `schemas`, plural. Using `schema` silently skips request parsing and docs wiring.
- Cookie names in runtime code are `seamless_access`, `seamless_refresh`, and `seamless_ephemeral`. Confirm docs and tests against those exact names.
- `system_config` can mask env changes after first bootstrap because the DB value becomes authoritative.
- Silent refresh and refresh-token matching depend on scanning active sessions and comparing bcrypt hashes, so session-heavy scenarios are worth extra care.

## 10. Suggested Workflow For Agents

1. Read the relevant route file.
2. Read the controller.
3. Read the service/helper/model touched by the controller.
4. Check the corresponding test file before editing.
5. If changing auth or schema behavior, inspect OpenAPI impact too.
6. Run `npm run build`, `npm run lint`, and targeted tests before wrapping up.
