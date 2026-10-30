# ADR 0001: OpenID Provider architecture

- **Status:** Accepted
- **Date:** 2026-10-29
- **Issue:** #404, part of epic #387 (v0.21 OpenID Provider)

## Context

Seamless Auth is an OAuth and OIDC client today (inbound providers in `src/services/oauthService.ts`) but not a provider. Every app that signs users in through it needs a Seamless SDK or server adapter. v0.21 makes the API an OpenID Provider (OP), so any app that speaks OpenID Connect can sign users in with no Seamless code.

The current architecture has three properties the provider has to work with:

- **Bearer only, no cookies.** The API returns tokens in JSON and never sets or reads browser cookies (AGENTS.md, `docs/architecture.md`, `docs/api-contract.md`). Browsers reach it through a trusted server adapter.
- **One token family.** First-party access and ephemeral tokens are RS256 JWTs with `iss` and `aud` equal to `ISSUER`, a `typ` claim of `access` or `ephemeral`, and keys from the secrets store (`src/utils/signingKeyStore.ts`). Refresh tokens are opaque, looked up by HMAC, and rotated through a chain of `sessions` rows with reuse detection (`src/controllers/authentication.ts`, `src/services/sessionService.ts`).
- **Routes are declared, not mounted.** Every endpoint goes through `defineRoute`, which validates against Zod schemas, generates `openapi.json`, and feeds the adapter manifest (`/.well-known/seamless-adapter.json`).

This ADR records how the provider is built and how it fits beside those properties. Every v0.21 implementation issue should be answerable from it. The issue map at the end points each issue at the sections that govern it.

## Decision summary

| #   | Decision                                                                                                                                       |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| D1  | Build on [`oidc-provider`](https://github.com/panva/node-oidc-provider) 9.x, wrapped in `src/oidc/`.                                           |
| D2  | The provider's issuer is `ISSUER + /oidc`, mounted at `/oidc` on the API origin.                                                               |
| D3  | The no-cookies invariant is revised: cookies exist only under `/oidc`, and no route outside it reads one.                                      |
| D4  | The provider signs with its own key set, separate from the first-party JWKS.                                                                   |
| D5  | Every hosted sign-in creates a linked row in `sessions` (mode `oidc`); provider refresh tokens use the library's rotation and reuse detection. |
| D6  | Storage is hybrid: one `oidc_payloads` JSONB table for library models, first-class tables for applications and resources.                      |
| D7  | Client secrets are derived from a server key, never stored.                                                                                    |
| D8  | Hosted login, consent and device pages are a prebuilt SPA from a new repo, served by the API like `/console`.                                  |
| D9  | Passkeys on the hosted page need the API origin under the configured `rpid`. Related Origin Requests are deferred.                             |
| D10 | `acr` and `amr` use registered values (OpenID EAP ACR values, RFC 8176).                                                                       |
| D11 | First-party tokens, `/refresh` and the existing JWKS are unchanged.                                                                            |
| D12 | Adapters do not proxy provider endpoints. They reach the new admin routes through the adapter manifest.                                        |
| D13 | A `system_config` flag, off by default, gates the provider endpoints until v0.21 is complete.                                                  |
| D14 | Account notices (#516) are an application-to-Seamless call on a client credentials token. v0.22 webhooks (#418) are the reverse direction.     |

## D1. Build on `oidc-provider`

We build on `oidc-provider` by Filip Skokan (panva) instead of writing a provider.

- **Certified.** It holds OpenID certifications for Basic, Implicit, Hybrid, Config, Form Post, 3rd Party-Init, RP-Initiated Logout, Back-Channel Logout and FAPI 2.0. Our own conformance run (#411) starts from a passing baseline instead of an empty one.
- **Coverage.** It already implements what the epic needs: authorization code with PKCE (S256 only since v9), refresh rotation with reuse detection, client credentials, device authorization (RFC 8628), introspection (RFC 7662), revocation (RFC 7009), resource indicators (RFC 8707), JWT access tokens (RFC 9068), RP-initiated and back-channel logout, loopback redirects on any port for native clients (RFC 8252), DPoP and PAR. Most API issues become configuration plus our storage adapter, account lookup and interaction UI.
- **Fit.** MIT licensed, so it can ship in this Apache-2.0 project. ESM only, needs Node 22 or later, and this API is already ESM on Node 22. Runtime dependencies are `koa`, `jose` (already ours) and `debug`. It mounts into Express with `app.use('/oidc', provider.callback())`.
- **Maintenance.** It has about 27 releases in the last 12 months (9.13.3 on 2026-10-29) and no open issues. It also has a single maintainer, which is the main risk.

Rules that contain that risk:

- Pin a 9.x minor and take upgrades deliberately (Dependabot groups it alone), with the conformance suite (#411) as the gate.
- Only `src/oidc/` imports `oidc-provider`. The rest of the API talks to the provider through our own module (account lookup, session linkage, storage, events). If we ever had to fork or replace it, the blast radius is that folder.
- The library ships no UI and no SQL adapter, and we write both (D6, D8).

Writing our own was rejected. Each RFC above, and keeping a certified conformance result green, would be ours to build and maintain. v0.21 would grow several times over for a worse result.

## D2. Issuer, mounting and request pipeline

- **Issuer:** `${ISSUER}/oidc`, for example `https://auth.example.com/oidc`. Discovery is at `/oidc/.well-known/openid-configuration`, and the provider's JWKS is at `/oidc/jwks`. A relying party (RP) only needs the issuer URL.
- **Why a path issuer.** Provider tokens then differ from first-party tokens in `iss`, signing keys (D4) and `aud`, so neither kind can be mistaken for the other. Nothing outside `/oidc` changes, and no root `/.well-known` route has to be forwarded into the provider.
- **Mount order in `src/app.ts`.** The provider is mounted after `helmet`, the trusted client context and the global rate limiters, and before `express.json()` and the CORS allowlist. The library parses its own bodies and warns when a body was already parsed. It also answers CORS for registered clients itself (`clientBasedCORS`), so `APP_ORIGINS` does not govern `/oidc`.
- **Proxies.** When `TRUST_PROXY` is set, `provider.proxy` is set too, so issuer-relative URLs and secure cookies are right behind a TLS-terminating proxy.
- **Helmet.** `frameguard: deny` stays. The hosted UI routes get a CSP that allows `form-action` to the client redirect URIs the library posts to, as the library's Express example does.
- **OpenAPI.** Endpoints the library serves are documented by discovery, not by `openapi.json`. The hosted UI's JSON endpoints (D8) and every admin route (#407, #509) go through `defineRoute` as usual, so they are validated and documented.
- **Configuration locked to OAuth 2.1 and RFC 9700 (#410).**
  - `responseTypes: ['code']`, with no implicit or hybrid flows.
  - `pkce.required` always returns true.
  - Exact redirect URI matching, except the RFC 8252 loopback port rule for native clients.
  - `rotateRefreshToken` always true.
  - `devInteractions` and dynamic registration are off.
  - HTTP POST to the authorization and logout endpoints stays off (the v9 default).
  - DPoP and PAR stay available as options.

  The admin API (#407) refuses client settings that would loosen any of these.

## D3. Cookies on the API origin

The hosted pages need a browser session at the provider, which means cookies on the API origin. The invariant is revised deliberately, and only for `/oidc`:

- **Who sets cookies.** Only the provider and the hosted UI under `/oidc` set cookies: `_session`, `_interaction` and `_interaction_resume`, renamed with a `seamless_oidc_` prefix through `cookies.names`. They are host-only, `Secure`, `HttpOnly`, `SameSite=Lax` and scoped to paths under `/oidc`.
- **Signing.** They are signed with keys from a new `OIDC_COOKIE_KEYS` secret, rotated by prepending a key.
- **Everything else.** No route outside `/oidc` sets or reads a cookie. First-party routes keep the bearer and JSON contract, and nothing in `verifyBearerAuth` or `attachAuthMiddleware` learns about cookies.

When the provider lands (#405, #406), these docs change in the same PR:

- **AGENTS.md (Auth Model).** "The API does not set or read browser auth cookies" becomes "Outside `/oidc`, the API does not set or read browser cookies. The OpenID Provider under `/oidc` keeps its own browser session in signed, host-only cookies scoped to that path (ADR 0001)."
- **AGENTS.md (Working Safely).** "Browser-cookie auth mode has been removed" gains the same `/oidc` exception.
- **`docs/architecture.md`.** The deployment topology gains a second path, browser to `/oidc` directly. Token Model gains a provider token section, and the "does not set or read browser auth cookies" line gains the same exception.
- **`docs/api-contract.md`.** "The API never sets cookies" is scoped to the JSON API.

## D4. Signing keys

The provider has its own key set, separate from the first-party JWKS:

- **Secrets.** `OIDC_JWKS_ACTIVE_KID`, plus a private JWK set under `OIDC_JWKS_KEYS`, both read through the existing secrets store. The prefix follows the same convention as the first-party keys. The library needs the private half of every key it publishes, so the set holds private keys.
- **Algorithm.** RS256, to match the first-party keys and what generic RPs expect. Other algorithms can be added later as extra keys.
- **Development.** A generated OP key is kept beside the existing dev signing key.
- **Rotation.** Add the new key to the set, so it is published at `/oidc/jwks`. Once RP JWKS caches have refreshed, make it active. Remove the old key after the longest provider token lifetime. The library takes keys at construction, so `src/oidc/` rebuilds the provider instance when the active kid or the set changes, on the same cache TTL `signingKeyStore` uses.
- **Effect on #405.** #405 says ID tokens are "signed with the existing JWKS". This ADR supersedes that: they are signed with the provider's keys and verified through `/oidc/jwks`.

The separate set keeps the blast radius apart. An RP that trusts the provider never trusts a first-party token, and a leaked provider key does not mint first-party sessions. It costs adopters a second rotation runbook, which `docs/production-operations.md` will document.

## D5. Sessions, refresh, step-up, recovery, audit and rate limits

### Linked sessions

- **One row per sign-in.** A hosted sign-in creates a row in `sessions` with `mode: 'oidc'` (the validator gains that value). Its `refreshTokenLookup` stays null. The row holds what it holds for first-party sign-ins: user, organization, user agent, IP, step-up time and method, recovery flag, and idle and absolute expiry.
- **The link.** The provider's Session record and every Grant and token issued under it carry that row's id in a `session_id` column on `oidc_payloads`. The `sid` claim in tokens is the provider's OIDC session id, as the logout specs define it. The link is kept server side.
- **Revoking a row ends everything under it.** That covers first-party logout, admin revoke, user sign-out everywhere, `sessionsRevokedBefore`, concurrent session eviction and chain revocation. It destroys the provider Session, revokes its grants with `revokeByGrantId` and sends back-channel logout to the affected clients (#409).
- **The reverse direction.** RP-initiated logout revokes the linked row.
- **Introspection (#511)** reports a token inactive as soon as its linked row is revoked.
- **Expiry.** The provider Session TTL follows the row's idle and absolute expiry (`session_idle_ttl` and the existing absolute TTL).
- **Client credentials** tokens have no user and no row.

### Refresh tokens (#408)

- **Rotation and reuse.** Provider refresh tokens use the library's rotation. A consumed refresh token presented again fails, and the library revokes the whole grant. That is the same reuse-detection guarantee the first-party chain gives, enforced in the provider's store instead of the `sessions` chain.
- **Not the first-party chain.** They do not create `sessions` chain rows, and `/refresh` never accepts them.
- **Issuance.** A refresh token is issued only to clients allowed the `refresh_token` grant that request `offline_access`.

### Step-up (#510)

- **Requesting it.** `acr_values` and `max_age` are honoured at the authorization endpoint through the library's login prompt checks.
- **Running it.** When they are not met, the hosted UI runs the step-up methods the first-party `/step-up/*` routes use, updates `stepUpVerifiedAt` and `stepUpMethod` on the linked row, and finishes the interaction.
- **Recording it.** The interaction finishes with `acr`, `amr` (D10) and `ts`, which becomes `auth_time`. They appear in ID tokens and JWT access tokens. Discovery lists `acr_values_supported`.

### Recovery sessions

- A hosted sign-in that only reaches a recovery session (`recovery: true`, from a recovery code) cannot finish the interaction.
- The hosted UI takes the user through enrolling a new factor, which clears the recovery flag as it does first-party. Only then does it complete the sign-in.
- A provider token is never issued for a half-recovered account.

### Audit

- Provider events (`grant.success`, `grant.error`, refresh reuse, `end_session.success`, `backchannel.error` and others) are mapped to `AuthEventService` events with new types, such as `oidc_authorize`, `oidc_token_issued`, `oidc_consent_granted`, `oidc_refresh_reuse`, `oidc_logout` and `oidc_backchannel_failed`.
- Application and resource changes (#407, #509) and account notices (#516) are audited the same way.
- Events carry the linked session id, so the existing auth event dimensions and exports work.

### Rate limits

- The global limiters apply to `/oidc`.
- Hosted UI steps reuse the existing `flow_rate_limits` buckets for the method they run (OTP, magic link, WebAuthn), so the hosted page is never a cheaper path than the JSON API.
- New buckets cover the token, device authorization, user code entry, introspection and notices endpoints.

## D6. Data model

Library-owned models live in one table. Things admins manage get first-class tables.

- **`oidc_payloads`.** Columns: `id`, `model`, `payload` (JSONB), `grant_id`, `user_code`, `uid`, `session_id`, `expires_at`, `consumed_at`. Unique on (`model`, `id`), with indexes for `grant_id`, `user_code`, `uid` and `expires_at`.
  - It holds Session, Interaction, AuthorizationCode, AccessToken (opaque), RefreshToken, ClientCredentials, DeviceCode, Grant (which is the consent record), PushedAuthorizationRequest and ReplayDetection.
  - The library's payload list grows between versions, so it is stored as JSONB and not as typed columns.
  - `ReplayDetection` and the inbound state cache insert only if absent (`ON CONFLICT DO NOTHING`), as the library requires from 9.13.2.
  - A purge job deletes rows past `expires_at`.
- **`oidc_clients`.** Client id, name, type (`public` or `confidential`), redirect URIs, post-logout redirect URIs, grant types, token endpoint auth method, back-channel logout URI, token lifetimes, `secret_version` (D7), device flow enabled, created and updated timestamps. The library's `Client.find` reads this table.
- **`oidc_resources`.** Identifier (an absolute URI, unique), name, scopes (name and description), access token lifetime. Access tokens for a resource are JWTs (RFC 9068, `typ: at+jwt`) with `aud` set to the identifier.
- **`oidc_client_resources`.** Which resources and which of their scopes each client may request. `getResourceServerInfo` reads it.
- **Consent** is the library's Grant. "Remembered consent" and revoking an app's access are queries and deletes on Grant rows.
- **Device codes** are `DeviceCode` rows. The user code is case-insensitive, from the library's base-20 charset with no look-alike characters.
- **OAuth state replay cache (#414).** `consumedStateHashes` in `oauthService.ts` moves into `oidc_payloads` with `model: 'OAuthStateReplay'` and `expires_at` set to the state lifetime. The table is migrated whether or not the provider is enabled, so #414 does not wait for D13.
- **Hosted UI branding (#406).** A new `system_config` key, `hosted_ui`, holds the logo URL, colors, fonts and an app name override. It is managed through the existing system config routes, so it needs no new admin route.

## D7. Client secrets

The library authenticates `client_secret_basic` and `client_secret_post` by comparing against the secret `Client.find` returns, so it needs a usable secret. We derive it instead of storing it:

- **Derivation.** `secret = HMAC-SHA256(OIDC_CLIENT_SECRET_KEY, client_id + ':' + secret_version)`, base64url encoded and computed inside `Client.find`.
- **Storage.** The database holds no secret, and a database dump alone reveals none. This is the same pattern as the refresh token lookup HMAC.
- **Issue and rotate.** The secret is shown once, at creation or rotation. Rotating increments `secret_version`, which invalidates the old secret at once.
- **Grace period.** A grace window for the old secret is out of scope for v0.21.
- **Disabled.** `client_secret_jwt` and the HS\* ID token algorithms stay disabled, because they would make the derived secret a signing key held by RPs.
- **Alternative.** `private_key_jwt` with a registered JWKS is offered for confidential clients that can use it.
- **Public clients** (native, SPA and device) have no secret and must use PKCE.
- **Key compromise.** If `OIDC_CLIENT_SECRET_KEY` leaks, every derived secret is exposed. Rotating that key rotates every client secret at once, which the runbook states.

## D8. Hosted login, consent and device pages

The hosted UI is a prebuilt SPA, shipped the way the admin console is:

- **Source.** A new repo, `fells-code/seamless-auth-hosted-ui`, built on `@seamless-auth/react`.
- **Shipping.** The API pins a released build and copies it into the image, as `build:console` pins the dashboard. It is served from `HOSTED_UI_DIR` under `/oidc`.
- **Interaction URL.** `interactions.url` is `/oidc/interaction/:uid`, which serves the SPA shell. The `_interaction` cookie is scoped to that path, so the SPA's JSON endpoints live beneath it: details, each sign-in method's steps, step-up, enrollment for recovery sessions, consent, and abort.
- **The JSON endpoints.** They are `defineRoute` routes declared `adapter: false` and authorized by the interaction (`provider.interactionDetails`). They call the existing services (WebAuthn, OTP, magic link, TOTP, recovery codes, step-up), not the first-party HTTP routes.
- **Finishing.** The endpoints finish with `provider.interactionResult`, which returns the redirect for the SPA to follow.
- **Methods shown.** Every method enabled in `login_methods` and the login policy is offered.
- **Consent.** It is shown for third-party clients and skipped for clients marked first-party, through `loadExistingGrant`.
- **Device verification (#515).** The library's user code input and confirmation hooks render the same SPA shell. The page shows the client's name and requested scopes before approval, against the remote phishing risk in RFC 8628 section 5.4.
- **Branding without a build.** The API injects `hosted_ui` and `app_name` as CSS variables and a JSON blob into the shell's `index.html` at serve time. Changing branding is a config write, and upgrading the bundle keeps it.
- **Accessibility.** WCAG 2.2 AA is the hosted UI repo's acceptance bar.

The new repo becomes a Tier 1 dependent (see affected repos below).

## D9. Passkeys on the hosted page

- **What deployments must do.** The API origin that serves `/oidc` must be the configured `rpid` or a subdomain of it, and must be listed in `origins`. For example, `https://auth.example.com` with `rpid` `example.com` works.
- **Enforcement.** Enabling the provider (D13) is refused, with a clear error, when the API origin is not covered.
- **Existing passkeys.** `rpid` does not change, so existing passkeys keep working on the hosted page. Changing `rpid` to fit a new hostname would orphan every existing passkey, and `docs/configuration.md` will warn against it.
- **Deferred.** Related Origin Requests (`/.well-known/webauthn`), for hosted pages on a different registrable domain, are out of scope for v0.21. A deployment that needs them can be tracked as its own issue.

## D10. `acr` and `amr` values

`amr` uses the RFC 8176 registry:

| Sign-in method                          | `amr`                                              |
| --------------------------------------- | -------------------------------------------------- |
| Passkey, device-bound (BE flag not set) | `hwk`, plus `user` and `mfa` when UV was performed |
| Passkey, synced or unknown              | `swk`, plus `user` and `mfa` when UV was performed |
| Email code or magic link                | `otp`                                              |
| SMS code                                | `sms`, `otp`                                       |
| TOTP                                    | `otp`                                              |
| Any two distinct factors in one session | `mfa` added                                        |

`acr` uses the OpenID Enhanced Authentication Profile ACR values:

- `phrh` for a device-bound passkey with user verification.
- `phr` for any passkey with user verification.
- Omitted otherwise.

`acr_values_supported` is `["phr", "phrh"]`. Seamless-specific names (such as `webauthn`) were rejected, because generic RPs and libraries would not recognise them. #510's examples are read with this mapping.

## D11. Compatibility

- **First-party contract unchanged (#509).** First-party access and ephemeral tokens, `/refresh`, `/.well-known/jwks.json`, `aud === ISSUER` and the adapter cookie flow all stay as they are.
- **Why the token kinds cannot be confused.** The first-party verifier requires `iss` and `aud` equal to `ISSUER`, a `typ` claim of `access` or `ephemeral`, and a first-party key. Provider tokens fail all four.
  - Provider tokens are signed with provider keys and carry `iss` of `${ISSUER}/oidc`.
  - ID tokens have `aud` set to the client id.
  - JWT access tokens have `aud` set to a resource identifier.
  - Access tokens without a resource are opaque and only usable at `userinfo`.
  - The admin API also refuses a resource identifier or client id equal to `ISSUER`.
- **Claims.**
  - `sub` is the user id.
  - Standard `email`, `email_verified`, `phone_number` and `phone_number_verified` follow the requested scopes.
  - `roles` and `org_id` are under a `seamless` scope.
  - `sid`, `acr`, `amr` and `auth_time` are as above.
  - `client_id` and `scope` appear on JWT access tokens.

  types#118 defines these.

- **Adapter manifest.** It is unchanged in shape. Provider endpoints are not in it, because adapters do not proxy them (D12).

## D12. Topology, adapters and admin routes

- **Direct access.** Browsers and RPs reach `/oidc` directly, not through a server adapter. A deployment that keeps the API private behind its adapter must expose the `/oidc` path publicly to use the provider. `docs/production-operations.md` states this.
- **New admin routes** go through `defineRoute` with `auth: 'access'` and the admin middleware, and already appear in `/.well-known/seamless-adapter.json` as access passthroughs:
  - `/admin/applications` (create, list, get, update, delete)
  - `/admin/applications/:id/secret` (rotate)
  - `/admin/resources`
  - `/admin/applications/:id/resources`
- **server#241.** The JS adapters start proxying admin routes from the manifest instead of hand registration, beginning with the v0.21 routes. That ends the per-route passthrough checklist for admin routes. Step-up and admin role checks stay in the API.
- **Branding** uses the existing system config routes (D6), so dashboard#319 and cli#320 need no new passthrough.
- **Verify-only resource servers** (server#239 and the Go, Python and Rust equivalents) take the issuer URL `${ISSUER}/oidc`. They fetch `/oidc/jwks` through discovery and check `aud`, `scope`, `acr`, `amr` and `auth_time` with the types#118 definitions.

## D13. Rollout

- **The flag.** A new `system_config` key, `oidc_provider_enabled`, defaults to `false`. It is seeded by `bootstrapSystemConfig` and read through the cached `getSystemConfig`.
- **While off.** `/oidc/*` answers 404 and the provider instance is not built, so main stays releasable for 0.20.x patches while v0.21 lands piece by piece.
- **While off, these still work:**
  - The admin routes for applications and resources.
  - The `hosted_ui` config.
  - The `oidc_payloads` migration, including the #414 state cache.

  The console, CLI and types can then be built and tested against main.

- **Turning it on.** A config write, guarded by the D9 origin check and by the presence of `OIDC_JWKS_*`, `OIDC_COOKIE_KEYS` and `OIDC_CLIENT_SECRET_KEY`.
- **Changing the default.** The default may only change when the whole epic is complete and #411 passes.

## D14. Account notices on an application's behalf (#516) and v0.22 webhooks (#418)

- **The endpoint.** `POST /oidc/api/account-notices` lives in the provider namespace and is gated by D13.
- **Authentication.**
  - A registered application calls it with a client credentials access token.
  - The token is issued for the built-in resource `${ISSUER}/oidc/api` with scope `notices:send`.
  - That resource is seeded, and an admin grants the scope per application.
- **Delivery.** It sends through `src/services/accountNotices.ts`, including external delivery (`account_notice_email`, `account_notice_sms`). The notice names the sending application.
- **Limits and audit.** Rate limits apply per client and per user, and every notice writes an auth event.
- **Request and response.** types#120 defines them. The response lists the channels used and never the addresses.

**Relation to #418.** The two are opposite directions on the same application record:

- #516 is the application calling Seamless. It is a command, authorized by OAuth scopes.
- #418 webhooks are Seamless calling the application. They are events, signed by Seamless and delivered to an endpoint registered on the application.

v0.22 adds webhook subscriptions to `oidc_clients` (or a table keyed by it) instead of a second application registry. The auth event a notice writes is one of the events a webhook can later carry. Neither feature depends on the other to ship.

## Inbound OAuth (#413, #414)

- **#413.** Discovery for inbound providers stays in `oauthService.ts` and is unrelated to `oidc-provider`. An inbound provider configured from an issuer URL fetches that issuer's discovery and JWKS with `jose`, as ID token verification already does.
- **#414.** The only shared piece is the replay table (D6).

## Consequences

- **Cookies.** The API is no longer cookie-free, and AGENTS.md and the architecture docs say exactly where cookies exist (D3).
- **Exposure.** The API now serves browsers directly on `/oidc`, which widens its public surface. Rate limits, CSP and the D13 flag contain this until v0.21 is complete.
- **Secrets.** Adopters manage three new secrets (`OIDC_JWKS_*`, `OIDC_COOKIE_KEYS`, `OIDC_CLIENT_SECRET_KEY`) and a second key rotation runbook.
- **Dependency risk.** A single-maintainer dependency sits on the critical path. `src/oidc/` isolation and conformance-gated upgrades keep it replaceable.
- **New repo.** The hosted UI lives in a new repo with its own release, pinned by the API.

## Issue map

| Issue            | Governed by                                                       |
| ---------------- | ----------------------------------------------------------------- |
| #405             | D1, D2, D4, D5 (linked sessions), D11 (claims), D13               |
| #406             | D3, D5 (step-up, recovery, rate limits), D6 (`hosted_ui`), D8, D9 |
| #407             | D6 (`oidc_clients`), D7, D12, D2 (#410 lock)                      |
| #408             | D5 (refresh), D6                                                  |
| #409             | D5 (linked sessions), D2                                          |
| #410             | D2 (configuration lock), D7                                       |
| #411             | D1, D13                                                           |
| #413             | Inbound OAuth                                                     |
| #414             | D6 (`OAuthStateReplay`)                                           |
| #508             | D2, D7 (public clients)                                           |
| #509             | D6 (`oidc_resources`), D11                                        |
| #510             | D5 (step-up), D10                                                 |
| #511             | D5 (linked sessions, rate limits), D6                             |
| #515             | D6 (device codes), D8                                             |
| #516             | D14                                                               |
| types#97         | D6, D7, D12 (admin route shapes)                                  |
| types#118        | D10, D11 (claims), D2 (discovery)                                 |
| types#120        | D14                                                               |
| server#239       | D11, D12                                                          |
| server#241       | D12                                                               |
| dashboard#296    | D6, D12                                                           |
| dashboard#319    | D6 (`hosted_ui`), D8                                              |
| cli#276, cli#320 | D12, D6                                                           |
| cli#316          | D2, D6 (device codes), D8                                         |

## Affected repos

This is a contract-affecting design (new routes, new token family, new auth surface). Using the map in `docs/ecosystem.md`:

- **seamless-auth-types (Tier 1).**
  - types#97: application and resource admin schemas.
  - types#118: claims, discovery, token responses and step-up challenge.
  - types#120: account notices.

  Published as 0.34.0 prereleases on `next` until the API settles.

- **seamless-auth-server (Tier 1).**
  - server#241: admin routes followed from the manifest.
  - server#239: verify-only guards against `${ISSUER}/oidc`.

  The cookie flow is unchanged.

- **seamless-auth-js (renamed from seamless-auth-react, Tier 1).** The hosted UI builds on it. The SDK contract is unchanged.
- **seamless-auth-hosted-ui (new, Tier 1).** The hosted pages (D8), pinned by this API.
- **seamless-messaging (Tier 1).** No change. Notices reuse `account_notice_*` delivery.
- **seamless-auth-admin-dashboard (Tier 2).** Applications page (#296) and branding settings (#319).
- **seamless-cli (Tier 2).** `seamless apps` (#276), branding (#320), and sign-in through the provider (#316).
- **seamless-templates and seamless-auth-docs (Tier 2).** Provider configuration, the deployment exposure requirement (D12), the key and secret runbook (D4, D7), and the provider docs (docs#114, docs#137).
- **seamless-auth-go, seamless-auth-python, seamless-auth-rust.** The verify-only guards follow D11 and types#118.

## Alternatives considered

- **Writing our own provider.** Rejected in D1.
- **Separate host for the provider, keeping the API cookie-free.** This would have meant a second listener or deployment. Rejected because every adopter would pay the operational cost, while scoping cookies to `/oidc` gives the same guarantee to the JSON API.
- **Provider sessions independent of `sessions`.** Rejected because every revocation path would need a second implementation, and introspection could not see first-party revocations.
- **Shared signing keys with the first-party JWKS.** Rejected so that trust in the provider and trust in first-party tokens stay separable (D4).
- **Server-rendered hosted pages.** Rejected in favour of a prebuilt SPA (D8). Branding stays build-free through injected CSS variables.
- **A table per library model.** Rejected because the library's payload set changes between versions.
- **Stored client secrets** (hashed or encrypted). Hashing is not possible with the library's comparison. Encryption adds a stored blob and a re-encryption step for the same exposure model as derivation (D7).
- **Issuer equal to `ISSUER`.** Rejected so that provider and first-party tokens also differ in `iss`, and so that no root `/.well-known` route is forwarded into the provider (D2).
