# Ecosystem & downstream impact

`seamless-auth-api` is the contract source for a family of sibling repos under the same
parent directory (`fells-code` org). This document is the **deep coupling map**:
what depends on this API, how, and what changes here ripple outward. `CLAUDE.md` carries
the short version + the ripple protocol; this file is the detail to read before/while
making a contract-affecting change.

> Last surveyed: 2026-06-27. Versions and line numbers drift — treat specifics as leads to
> re-verify, not gospel. Re-run the survey when the dependency graph changes.

## Topology

```
browser
  └─ @seamless-auth/react ............ client SDK (cookie-based session)
        └─ @seamless-auth/express ..... server adapter (cookies ⇄ Bearer, JWKS verify)
              └─ THIS API (seamless-auth-api) ... Bearer/JSON contract, no cookies
                    ├─ @seamless-auth/types ..... shared Zod schemas (this API consumes)
                    └─ @seamless-auth/messaging* . email/SMS adapter contract (this API consumes)
```

Note the auth-style boundary: the **React SDK uses cookies** (`credentials: 'include'`),
while **this API is Bearer/JSON with no cookies** (see README "Bearer Token Contract").
The **server adapter** (`@seamless-auth/express` / `@seamless-auth/core`) is what bridges
them — it holds `seamless-access` / `seamless-refresh` / `seamless-ephemeral` cookies on
the browser side and speaks Bearer + service tokens + JWKS to this API. Direct
browser→API integration is possible ("Direct HTTP APIs (advanced)") but the recommended
path goes through the adapter.

## Tier 1 — direct contract dependents

### `seamless-auth-server` — `@seamless-auth/core` + `@seamless-auth/express` (v0.5.x)

The server-side adapter SDK; a thin stateless proxy + cookie manager. **Highest coupling.**

- Calls ~50 of this API's routes via `authFetch()` with `Authorization: Bearer`,
  `x-seamless-service-token`, `x-seamless-client-ip`. Covers `/login`, `/registration/register`,
  all `/otp/*`, `/webAuthn/*`, `/magic-link*`, `/refresh`, `/users/*`, `/organizations/*`,
  `/step-up/*`, `/sessions*`, all `/admin/*`, all `/internal/*`, `/system-config/*`.
- **JWKS:** fetches `/.well-known/jwks.json` (`createRemoteJWKSet` + `jwtVerify`, RS256),
  validates `iss` against the auth server URL. Reads claims `sub`, `sid`, `aud`, `iss`.
- **Refresh:** POST `/refresh` response unpacked directly into cookies — expects
  `sub, token, refreshToken, ttl, refreshTtl, roles?, email?, phone?, organizationId?`.
- **Status-code coupling:** branches on exact codes, e.g. magic-link poll treats `204` as
  "not yet verified".
- No shared types package — coupling is 100% string-literal route paths + response shapes.
- **Breaks if this API changes:** any route path/method, JWKS path or key format/alg, token
  claim/field names (`sub`/`sid`/...), the `/refresh` response shape, or branch-significant
  status codes.

### `seamless-auth-react` — `@seamless-auth/react` (v0.2.0)

Drop-in React auth UI (email/phone OTP, magic link, WebAuthn/passkeys, OAuth, step-up,
organizations). Hardcodes ~38 endpoint paths in `src/createSeamlessAuthClient.ts`.

- Parses response fields for flow control: `message === 'Success'`, plus `token`,
  `refreshToken`, `delivery`, and the `/users/me` shape (`user`, `credentials[]`,
  `organizations[]`, `activeOrganization`).
- Generic error handling (trusts `response.ok`), so contract breaks often fail **silently**.
- **Breaks if this API changes:** route renames, `message`/user/credential field renames,
  switching an endpoint's auth mode (ephemeral ↔ access), or response-shape changes to
  `/users/me`, OTP, or organization endpoints.

### `seamless-auth-types` — `@seamless-auth/types` (v0.1.3) ⇠ this API depends on it

Shared Zod schemas / TS types — the contract's source of truth. **Reverse coupling:** changes
here propagate _into_ this API and the SDKs.

- This API imports it at 5 sites: `schemas/internal.responses.ts` (`AuthEventSchema`),
  `schemas/credential.responses.ts` (`CredentialApiSchema`, extended),
  `schemas/admin.responses.ts` (`AuthEventSchema`, `SessionSchema`),
  `schemas/session.responses.ts` (`SessionSchema`),
  `routes/users.routes.ts` (`UpdateCredentialRequestSchema`, `DeleteCredentialRequestSchema`).
- **Highest-risk exports:** credential request/response schemas (used in route validation),
  `AuthEventSchema` (snake_case, serialized directly), `SessionSchema`, `RoleSchema`.
- ⚠️ **Known drift:** `RoleSchema`'s regex is **duplicated** in this API at
  `src/lib/scopedRoles.ts:6` (`ROLE_NAME_PATTERN`) instead of imported — they can silently
  diverge. Consider importing from the types package.
- **Breaks if changed here:** rename/remove an exported schema, change/tighten a field or
  validator (e.g. `RoleSchema` regex), change `IsoDate` transform → forces coordinated
  releases across this API + both SDKs.

### `seamless-messaging` — `@seamless-auth/messaging` (+ `-aws`, `-twilio`, v0.1.0) ⇠ this API depends on it

Provider-agnostic email/SMS adapter contract. **Reverse coupling.**

- This API consumes it at `src/config/directMessaging.ts` (factory + AWS/Twilio transports,
  `MessagingConfigurationError`) and `src/services/messagingService.ts` (calls
  `sendOtpEmail`, `sendOtpSms`, `sendMagicLinkEmail` 1:1). `sendBootstrapInviteEmail` is part of the
  adapter contract but no longer called by this API.
- Core contract: `EmailTransport` / `SmsTransport` (`send()` + `name`), `AuthMessagingService`
  (the 4 send methods), and the `Send*Input` payload types (`to`, `token`, `magicLinkUrl`, …).
- **Breaks if changed here:** `AuthMessagingService` method signatures/payloads, transport
  `send()` signature, package renames, new required adapter config, or removing
  `MessagingConfigurationError`.

## Tier 2 — downstream consumers (transitively affected)

| Repo                               | What it is                                                | Coupling                                                                                         |
| ---------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `seamless-auth-admin-dashboard`    | Admin UI                                                  | `@seamless-auth/react` + `@seamless-auth/types`; consumes `/admin/*` + `/internal/*` via the SDK |
| `seamless-templates`               | Express + React starter templates (scaffolded by the CLI) | `@seamless-auth/express` and `@seamless-auth/react`; break only if those SDK public APIs change  |
| `seamless-auth-internal-api`       | Internal/enterprise API variant                           | Tracks this codebase closely; likely needs parallel changes for shared logic                     |
| `seamless-auth-docs`               | Public docs                                               | Documents the HTTP contract — update when routes/schemas change                                  |
| `seamless-cli` (`create-seamless`) | Scaffolding CLI                                           | Generates projects wired to the SDKs                                                             |

## High-risk contract surfaces (change = survey downstream)

1. **Route paths / methods** — `src/routes/*.routes.ts`. Hardcoded as strings in both SDKs.
2. **Response schemas** — `src/schemas/*.responses.ts`. Field renames/removals break parsing.
3. **Token contract** — access/refresh/ephemeral/service tokens, claim names (`sub`, `sid`),
   the `/refresh` response shape, JWKS at `/.well-known/jwks.json` (RS256).
4. **Status / error codes** — adapters branch on specific codes (e.g. magic-link `204`).
5. **Shared schemas** in `@seamless-auth/types` and the **messaging adapter contract**.
6. **Auth mode** of a route (ephemeral vs access vs service) — see
   `src/middleware/attachAuthMiddleware.ts`.
