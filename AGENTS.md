## Seamless Auth API Agent Guide

This repository is an Express + TypeScript authentication service for passwordless auth flows. It supports WebAuthn/passkeys, OTP, magic links, JWKS publication, session management, admin endpoints, and a small system configuration layer persisted in Postgres.

Use this file as the fast path. For the deeper architecture walkthrough, see [docs/architecture.md](/Users/brandoncorbett/git/seamless-auth-api/docs/architecture.md).

## Working Standards (fells-code baseline)

These rules apply to every repository in the fells-code org. Repo-specific
guidance may extend them but must not contradict them.

### Attribution

- Commit and open PRs solely under the repository owner's identity. Never
  commit under an agent or assistant identity.
- Never attribute work to an AI assistant: no `Co-Authored-By: Claude` (or any
  assistant) trailers, no "Generated with" / "Created with Claude" notes, and no
  assistant branding or emoji anywhere in commit messages, PR or issue titles
  and descriptions, changesets, code comments, or docs.

### Comments

- Comment only when the code genuinely needs explaining: a non-obvious reason, a
  gotcha, or an invariant. Never narrate what the code plainly does.

### TODOs

- Every `TODO`/`FIXME` must reference a ticket, e.g. `// TODO(#123): ...`.
  Do not leave a bare TODO. If no ticket exists, create one first.

### Commits & branches

- Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `ci:`, `test:`).
- Descriptive branch names (`feat/...`, `fix/...`); never a `claude/` or other
  tool-generated prefix.

### Public-facing text

- No em dashes in commit messages, code comments, PR or issue text, changesets,
  or docs. Use a comma, parentheses, or a separate sentence.

### Before declaring work done

- All code quality checks must pass before you open a PR or call the work done:
  tests, linting, type checks, and formatting. Run them and report the real
  output; do not open a PR while any check is failing.
- Typical commands: `npm run typecheck`, `npm run lint`, `npm run format:check`
  (or `npm run format`), and `npm test`. Never claim a change works without
  running them.
- Match the surrounding code's style, naming, and comment density.

## Start Here

- Install dependencies: `npm install`
- Run in development: `npm run dev`
- Type-check/build: `npm run build`
- Lint: `npm run lint`
- Run tests once: `npm run test:run`
- Coverage: `npm run coverage`

The service starts from [src/server.ts](/Users/brandoncorbett/git/seamless-auth-api/src/server.ts), which initializes models, connects to the database, bootstraps `system_config`, builds the Express app, and begins listening.

## Core Runtime Shape

- [src/app.ts](/Users/brandoncorbett/git/seamless-auth-api/src/app.ts): global middleware, CORS, OpenAPI docs in dev, rate limiting, and top-level error handlers.
- [src/lib/loadRoutes.ts](/Users/brandoncorbett/git/seamless-auth-api/src/lib/loadRoutes.ts): dynamically imports every `*.routes.ts` file under `src/routes`.
- [src/lib/createRouter.ts](/Users/brandoncorbett/git/seamless-auth-api/src/lib/createRouter.ts): thin wrapper used by route modules.
- [src/lib/defineRoute.ts](/Users/brandoncorbett/git/seamless-auth-api/src/lib/defineRoute.ts): registers Express handlers and OpenAPI metadata, validates request payloads, and optionally validates JSON responses.

When tracing behavior, start at the route file, then the controller, then the service/model/helper layers.

## Important Folders

- [src/routes](/Users/brandoncorbett/git/seamless-auth-api/src/routes): endpoint registration
- [src/controllers](/Users/brandoncorbett/git/seamless-auth-api/src/controllers): request handling
- [src/services](/Users/brandoncorbett/git/seamless-auth-api/src/services): session issuance, messaging, bootstrap promotion, auth event logging
- [src/models](/Users/brandoncorbett/git/seamless-auth-api/src/models): Sequelize models
- [src/config](/Users/brandoncorbett/git/seamless-auth-api/src/config): bootstrapped system config, required config metadata
- [src/lib](/Users/brandoncorbett/git/seamless-auth-api/src/lib): routing, cookies, tokens, OpenAPI helpers
- [src/middleware](/Users/brandoncorbett/git/seamless-auth-api/src/middleware): auth, rate limits, logging
- [tests](/Users/brandoncorbett/git/seamless-auth-api/tests): unit, integration, e2e, and shared factories/setup

## Auth Model

There are three token states worth keeping straight:

- Ephemeral token: short-lived pre-auth token used to continue registration/login flows.
- Access token: signed JWT used for authenticated application access.
- Refresh token: opaque random token stored hashed in the `sessions` table.

The API exposes a single bearer/JSON auth contract:

- Ephemeral, access, and refresh tokens are returned in JSON response payloads.
- Protected routes expect bearer credentials from a trusted server adapter or backend.
- The API does not set or read browser auth cookies.

Auth middleware is chosen centrally by [src/middleware/attachAuthMiddleware.ts](/Users/brandoncorbett/git/seamless-auth-api/src/middleware/attachAuthMiddleware.ts).

## Config Model

There are two config layers:

- Environment variables: needed to boot the process and connect external systems.
- `system_config` table: runtime configuration such as token TTLs, origins, roles, and WebAuthn RP settings.

[src/config/bootstrapSystemConfig.ts](/Users/brandoncorbett/git/seamless-auth-api/src/config/bootstrapSystemConfig.ts) seeds missing `system_config` rows from env vars at startup. [src/config/getSystemConfig.ts](/Users/brandoncorbett/git/seamless-auth-api/src/config/getSystemConfig.ts) caches reads in-process, so remember to invalidate the cache after writes.

## Messaging And Delivery

OTP and magic link flows can operate in two modes:

- Direct delivery: the API sends email/SMS itself via [src/services/messagingService.ts](/Users/brandoncorbett/git/seamless-auth-api/src/services/messagingService.ts).
- External delivery: callers send header `x-seamless-auth-delivery-mode: external` and the API returns delivery payloads instead of sending them directly.

Direct provider wiring currently lives in [src/config/directMessaging.ts](/Users/brandoncorbett/git/seamless-auth-api/src/config/directMessaging.ts).

## Working Safely In This Repo

- Prefer changing controllers/services over adding logic directly in routes.
- When adding or updating routes, use `schemas`, not `schema`, so request parsing and OpenAPI generation both work.
- If a route requires auth, prefer the `auth` option in `createRouter` definitions. That keeps middleware wiring and OpenAPI security metadata aligned.
- If a route also needs admin checks or rate limiting, combine `auth` with extra `middleware`.
- Be careful around token response shapes and bearer auth. Browser-cookie auth mode has been removed.
- Preserve existing local worktree changes unless the user explicitly asks you to clean them up.
- Comment, attribution, TODO, and public-facing-text rules live in Working Standards above.

## Before You Finish A Change

- Run `npm run build`
- Run `npm run lint`
- Run targeted tests for the touched area when practical
- If you change request/response schemas or route auth, inspect the generated `/openapi.json` behavior in dev

## Known Maintenance Traps

- OpenAPI security metadata is only added when routes use the `auth` field in route definitions. Routes that manually call `attachAuthMiddleware(...)` can drift from the documented security model.
- Cookie names in runtime code should be treated as the source of truth when checking auth behavior.
- `system_config` values may come from the database even when `.env` changes, so config bugs are not always fixed by editing env vars alone.
