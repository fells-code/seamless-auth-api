# ADR 0001: OpenID Provider architecture

- **Status:** Accepted
- **Date:** 2026-10-29
- **Issue:** #404, part of epic #387 (v0.21 OpenID Provider)

## Context

Seamless Auth is an OAuth and OIDC client today (inbound providers in `src/services/oauthService.ts`) but not a provider. Every app that signs users in through it needs a Seamless SDK or server adapter. v0.21 makes Seamless an OpenID Provider (OP), so any app that speaks OpenID Connect can sign users in with no Seamless code.

The current architecture has three properties the provider has to respect:

- **The API is bearer only, with no cookies.** It returns tokens in JSON and never sets or reads browser cookies (AGENTS.md, `docs/architecture.md`, `docs/api-contract.md`). Browsers reach it through a trusted server adapter, and the API can run on a private network that only the adopter's backends reach.
- **First-party tokens are one family.** Access and ephemeral tokens are RS256 JWTs with `iss` and `aud` equal to `ISSUER` and a `typ` claim, signed with keys from the secrets store (`src/utils/signingKeyStore.ts`). Refresh tokens are opaque, looked up by HMAC, and rotated through a chain of `sessions` rows with reuse detection.
- **Sign-in protections live in the JSON routes.** Account-enumeration decoys (`src/controllers/decoyResponders.ts`), lockout, flow rate limits, `phishing_resistant_only` and the rule that an ephemeral token proves an address but not the account are all enforced by the first-party routes and their controllers.

An earlier draft of this ADR put the provider inside the API, on `/oidc`. A security review found that this design:

- Made the API internet facing.
- Revised the no-cookies invariant.
- Made the hosted pages call services directly, so each protection above had to be copied and kept in step.
- Left the provider's signing keys and every client secret on the public tier.

This version moves the provider out of the API.

## Decision summary

| #   | Decision                                                                                                                                                             |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| D1  | The OpenID Provider is a separate public service, the **login edge**, built on `oidc-provider` 9.x and `@seamless-auth/express`, in a new repo.                      |
| D2  | The auth API stays private, bearer only and cookie-free. Only the adopter's backends and the edge reach it.                                                          |
| D3  | The edge signs users in through the first-party JSON routes, like any Seamless app. A provider sign-in is an ordinary first-party session.                           |
| D4  | Provider signing keys stay in the API. The edge asks the API to sign, and the API signs only for a subject with a live session and the auth context it earned.       |
| D5  | Provider state lives in the API's Postgres (hybrid: one JSONB table, plus first-class tables for applications and resources), reached through service-token routes.  |
| D6  | Confidential clients use `private_key_jwt` by default. Public clients use PKCE. Shared secrets are an opt-in for compatibility, off by default and hashed at rest.   |
| D7  | The hosted login, consent and device pages are a SPA in the edge repo, built on `@seamless-auth/react`. Branding is config, injected at serve time.                  |
| D8  | The edge's hostname must sit under the configured `rpid`. Related Origin Requests are deferred.                                                                      |
| D9  | `acr` and `amr` use registered values (OpenID EAP ACR values, RFC 8176). The API, not the edge, decides them.                                                        |
| D10 | Device flow and third-party consent get explicit limits against consent phishing.                                                                                    |
| D11 | First-party tokens, `/refresh` and `/.well-known/jwks.json` are unchanged. Provider tokens can never pass as first-party ones.                                       |
| D12 | Admin routes for applications and resources live on the API, and adapters reach them through the adapter manifest.                                                   |
| D13 | The API's edge routes stay off behind a `system_config` flag until v0.21 is complete. Adopters opt in by deploying the edge.                                         |
| D14 | Account notices (#516) stay on the private API, limited to apps a user already uses. v0.22 webhooks (#418) are the reverse direction on the same application record. |

## Topology

```
any OIDC app ──► login edge (public: OIDC endpoints, hosted pages, cookies)
                      │   bearer + its own service token
SDK apps ─► adapter ──┤
                      ▼
               auth API (private, no cookies) ── Postgres
```

- **What the edge holds.** Browser sessions (cookies), the OIDC protocol and the hosted UI.
- **What the API holds.** Users, credentials, sessions, provider state, signing keys, the client registry, audit and policy. It does every sign-in check.
- **What the edge cannot do.** It cannot sign anyone in without the API, and it cannot mint a token the API would not sign.

## D1. The login edge, built on `oidc-provider`

The edge is a new Node service in a new repo, `fells-code/seamless-auth-oidc-provider`. It contains:

- **`oidc-provider`** 9.x by Filip Skokan (panva), for the protocol.
- **`@seamless-auth/express`**, for the browser session and the calls to the API.
- **The hosted UI** (D7).

It is released as a Docker image and as an npm package, so it can run as a service or be mounted into an adopter's own Express app.

Why `oidc-provider`:

- **Certified.** It holds OpenID certifications for Basic, Implicit, Hybrid, Config, Form Post, 3rd Party-Init, RP-Initiated Logout, Back-Channel Logout and FAPI 2.0.
- **Coverage.** It already implements what the epic needs:
  - Authorization code with PKCE (S256 only since v9).
  - Refresh rotation with reuse detection, and client credentials.
  - Device authorization (RFC 8628), introspection (RFC 7662) and revocation (RFC 7009).
  - Resource indicators (RFC 8707) and JWT access tokens (RFC 9068).
  - RP-initiated and back-channel logout.
  - Loopback redirects on any port for native clients (RFC 8252), DPoP and PAR.
- **Fit.** It is MIT licensed, ESM only and needs Node 22. Its runtime dependencies are `koa`, `jose` and `debug`, and it mounts into Express.

The library has a single maintainer. In this design it runs only in the edge, never in the API, so a library defect or upgrade cannot affect the core API. The edge pins a 9.x minor, upgrades it on its own, and gates each upgrade on the conformance suite (#411).

Writing our own provider was rejected. Each RFC above, and keeping a certified result green, would be ours to build and maintain.

**Locked configuration (#410).**

- Only the `code` response type: no implicit or hybrid.
- PKCE required for every client.
- Exact redirect URI matching, except the RFC 8252 loopback port rule.
- Refresh tokens always rotated.
- `devInteractions` and dynamic registration off.
- HTTP POST to the authorization and logout endpoints off.

DPoP and PAR are available. The API's admin routes refuse client settings that would loosen this list (D12).

**Issuer.** The edge's public URL, for example `https://login.example.com`, is stored in `system_config` as `oidc_issuer`. Discovery is at `/.well-known/openid-configuration` on the edge, and the provider JWKS is at `/jwks`. The API refuses an `oidc_issuer` equal to `ISSUER`.

## D2. The API stays private

- **No public surface.** The API gains no public endpoint and no cookie. AGENTS.md, `docs/architecture.md` and `docs/api-contract.md` keep their bearer-only, no-cookies statements unchanged.
- **New route groups.**
  - Admin routes for applications and resources (D12).
  - Service-token routes for the edge under `/oidc/*` (provider storage, signing, auth context, events). Despite the name, these are not the public OIDC endpoints. Those are served by the edge, and `/oidc/*` on the API answers only the edge's service token.
  - The notices endpoint (D14).
- **How the edge routes are declared.** They are `defineRoute` routes, authenticated with the edge's service token, declared `adapter: false` and documented in `openapi.json`.
- **The edge has its own service token.** It is signed with `SEAMLESS_OIDC_SERVICE_TOKEN`, a secret separate from the adapters' `SEAMLESS_SERVICE_TOKEN`, and the API refuses to start if the two are equal. The edge never holds the adapter secret.
  - `/oidc/*` accepts only the edge's token. An adapter's token gets 401 there.
  - Outside `/oidc/*`, the edge's token is honoured only for the trusted client context headers (`x-seamless-client-ip`, `x-seamless-client-user-agent`), so its first-party sign-ins see real users.
  - External delivery (`x-seamless-auth-delivery-mode: external`) refuses it. With the shared token, a compromised edge could ask for any user's OTP or magic link, complete a first-party sign-in as that user, and then have `/oidc/sign` sign for them, which defeats D4.
  - `oidc_provider_enabled` cannot be turned on without `SEAMLESS_OIDC_SERVICE_TOKEN` (D13).
- **Docs.** `docs/architecture.md` gains the edge in its deployment topology and a provider token section. `docs/ecosystem.md` gains the edge repo as a Tier 1 dependent.

## D3. Sign-in goes through the first-party routes

- **Signing in.** The hosted UI signs a user in with the same first-party routes every SDK app uses: `/login`, `/registration/*`, the WebAuthn, OTP, magic link and TOTP routes, `/step-up/*` and the recovery routes. It goes through the edge's own `@seamless-auth/express` adapter, so the edge holds the first-party access and refresh tokens in its session cookie, exactly as any adapter does.
- **Finishing the provider sign-in.** When the first-party sign-in succeeds, the edge finishes the OIDC interaction for that user. `accountId` is the user id, and the auth context comes from the API (D9).

What follows from this:

- **No copied protections.** Decoys, lockout, flow rate limits, `phishing_resistant_only` and the login policy all apply to hosted sign-in, because hosted sign-in is first-party sign-in. The edge forwards the browser's IP and user agent through the trusted client context headers, so the limits see real users.
- **The ephemeral-token rule carries over.** Proving an address unlocks nothing. Passkey and TOTP enrollment need an access session, as they do today.
- **Linked sessions need no new mode.** Every provider sign-in is an ordinary `sessions` row. The provider's Session, Grants and tokens carry that row's id in `session_id` (D5).
- **App refreshes keep the session alive.** Each provider token the API signs for the session counts as activity on it, so an app that refreshes its tokens moves the session's idle expiry forward. The session's absolute lifetime (`refresh_token_ttl`) still bounds it, so provider access never outlives the first-party session.
- **What revoking the row does.** Logout, admin revoke, user sign-out everywhere, `sessionsRevokedBefore`, concurrent session eviction and chain revocation all end the provider session too:
  - The API deletes the provider rows for that session.
  - It refuses to sign further for it.
  - It sends back-channel logout to the affected clients (#409).
- **Back-channel logout is sent by the API.** The API holds the keys and the client registry, and already makes outbound calls for messaging.
- **RP-initiated logout** at the edge revokes the row through `/logout`.
- **Recovery sessions.** A sign-in that only reaches a recovery session (`recovery: true`) cannot finish the interaction. The hosted UI takes the user through enrolling a new factor first, as first-party apps do.
- **Step-up (#510).** When `acr_values` or `max_age` are not met, the hosted UI runs `/step-up/*` with the access token. The API records it on the session row as it does today.

## D4. Signing stays in the API

- **The keys.** The provider has its own RS256 key set, separate from the first-party JWKS: `OIDC_JWKS_ACTIVE_KID` and a private JWK set in `OIDC_JWKS_KEYS`, in the API's secrets store. The edge never holds a private key.
- **How the edge signs.** It uses `oidc-provider`'s external signing support and calls `POST /oidc/sign`. The API signs only when all of these hold:
  - The request carries the edge's own service token (D2). The adapters' shared token is refused.
  - For ID tokens and user access tokens, `sub` has a live, unrevoked session matching the token's `session_id`, and that session holds a provider grant for the requesting client. Any other live session the edge learns of does not qualify.
  - Identity claims (`email`, `phone_number`, `roles`, `org_id` and the `_verified` flags) equal the account's own, and the token carries no claim outside what the library issues for its kind.
  - `acr`, `amr` and `auth_time` equal what the API recorded for that session (D9). The edge cannot raise them.
  - `aud` is the requesting client (ID tokens) or a resource that client may use (access tokens). `iss` is `oidc_issuer`.
  - For client credentials tokens, the client is active and allowed that grant, resource and scope.
- **The same binding for lookups.** `GET /oidc/accounts/:id` and `GET /oidc/sessions/:id/auth-context` answer only for a live session holding a provider grant for the calling client, which the edge names in the query. So the edge saves the Grant when the user signs in, before it reads the auth context to finish the login.
- **What this buys.** If the edge is compromised, the attacker can only get tokens for users who are signing in at that moment, and only with the assurance they actually reached. They cannot mint tokens for anyone else, cannot read other users' claims, cannot receive anyone's codes or magic links (D2), and cannot steal keys.
- **Publishing.** The edge serves the public JWKS at `/jwks`, read from `GET /oidc/jwks`.
- **Rotation.** Add a key, which publishes it. Once RP JWKS caches refresh, make it active. Remove the old key after the longest provider token lifetime. `docs/production-operations.md` gains this runbook.
- **Fallback.** External signing is marked experimental in `oidc-provider`. If it proves unreliable, the fallback is keys on the edge with short token lifetimes and alerting on unexpected `sub` values. That loses the protection above, so taking it needs an update to this ADR.
- **Effect on #405.** It said "ID tokens signed with the existing JWKS". This ADR supersedes that.

## D5. Data model and storage

Provider state lives in the API's Postgres. The edge's `oidc-provider` storage adapter calls `/oidc/payloads/*`, so there is one database and the API owns it.

- **`oidc_payloads`.** Columns: `id`, `model`, `payload` (JSONB), `grant_id`, `user_code`, `uid`, `session_id`, `expires_at`, `consumed_at`. Unique on (`model`, `id`), with indexes for `grant_id`, `user_code`, `uid`, `session_id` and `expires_at`.
  - It holds Session, Interaction, AuthorizationCode, AccessToken (opaque), RefreshToken, ClientCredentials, DeviceCode, Grant (the consent record), PushedAuthorizationRequest and ReplayDetection.
  - JSONB, because the library's payload list grows between versions.
  - `ReplayDetection` writes insert only if absent.
  - A purge job deletes expired rows.
- **`oidc_clients`.** Client id, name, first-party or third-party, type (`public` or `confidential`), token endpoint auth method, JWKS or JWKS URI (`private_key_jwt`), secret hash (D6), redirect URIs, post-logout redirect URIs, grant types, back-channel logout URI, token lifetimes, device flow enabled, notices enabled (D14), timestamps.
- **`oidc_resources`.** Identifier (an absolute URI, unique, never `ISSUER` or `oidc_issuer`), name, scopes, access token lifetime. Access tokens for a resource are JWTs (RFC 9068, `typ: at+jwt`) with `aud` set to the identifier.
- **`oidc_client_resources`.** Which resources, and which of their scopes, each client may request.
- **Auth context on `sessions` (#510).** New columns `auth_methods` (the methods used, with passkey device-bound or synced) and `auth_time`. Sign-in and step-up update them, and D9 derives `acr` and `amr` from them.
- **OAuth state replay cache (#414).** `consumedStateHashes` in `oauthService.ts` moves into `oidc_payloads` (`model: 'OAuthStateReplay'`), written only if absent. The table is migrated whether or not the provider is in use, so #414 does not wait for the edge.
- **Hosted UI branding (#406).** A `hosted_ui` key in `system_config` holds the logo URL, colors, fonts and an app name override. It is managed through the existing system config routes.
- **Abuse limits.** `/oidc/payloads/*` is rate limited per model, so a misbehaving edge cannot flood the store.

## D6. Client authentication

| Client type                                   | Authentication                                |
| --------------------------------------------- | --------------------------------------------- |
| Confidential (server-side web apps, services) | `private_key_jwt` by default                  |
| Public (SPA, native, CLI, device)             | none, with PKCE required                      |
| Confidential, opted in to a shared secret     | `client_secret_basic` or `client_secret_post` |

**Default: `private_key_jwt`.** Nothing secret is stored or derived on the Seamless side. A breach of the API or the edge cannot be used to impersonate a client. The edge's replay detection makes each assertion single use.

**Shared secrets, for compatibility.** Many off-the-shelf apps (Grafana, GitLab, Argo CD, Nextcloud, most SaaS connectors) only support shared secrets, and they are part of "any OIDC app". So:

- An instance-wide `allow_client_secrets` flag, off by default, enables them.
- An admin then opts each client in. The console and CLI label those clients as weaker.
- A secret is 32 random bytes, shown once, and stored as an HMAC lookup with a server key, as refresh tokens are. It is never stored in usable form.
- **Verification.** The edge checks a presented secret against the API before the library runs (`POST /oidc/clients/:id/verify-secret`). It then hands the verified value to the library for that request only.
- **Fallback.** If that request-scoped handoff does not fit the library cleanly, the fallback is a secret derived from a server key, computed by the API and returned to the edge only over the service channel. That fallback means the API's key can recompute every secret, so taking it needs an update to this ADR.
- **Disabled outright.** `client_secret_jwt` and HS\* ID token algorithms, which would turn a shared secret into a signing key.

## D7. Hosted login, consent and device pages

- **What it is.** A SPA in the edge repo, built on `@seamless-auth/react`. It talks to the edge's own adapter routes (same origin), exactly like an SDK app.
- **Methods shown.** Every method enabled in `login_methods` and the login policy.
- **Consent.** Shown for third-party clients and skipped for first-party ones. The consent page shows the client's name, its redirect domain and the requested scopes (D10).
- **Device verification (#515).** It runs in the same SPA, with the limits in D10.
- **Branding without a build.** The edge reads `hosted_ui` and `app_name` from the API and injects them as CSS variables and a JSON blob into `index.html` at serve time. Changing branding is a config write, and upgrading the edge keeps it.
- **Accessibility.** WCAG 2.2 AA is the edge repo's acceptance bar.
- **Cookies.**
  - The provider session cookie and the adapter session cookie both use the `__Host-` prefix: host-only, `Secure`, `Path=/`. A sibling subdomain cannot plant or shadow them.
  - Both are `HttpOnly` and `SameSite=Lax`.
  - The provider cookies are signed with an edge secret, `OIDC_COOKIE_KEYS`.
- **CSRF.** RPs often sit on sibling subdomains, which count as same-site, so `SameSite` alone is not enough. Every state-changing route on the edge checks `Sec-Fetch-Site` and `Origin`. This is the guard `@seamless-auth/core` already implements.
- **CSP.** Strict: scripts and styles only from self, `frame-ancestors 'none'`, and `form-action` limited to self and the client's redirect URIs.
- **Pinning.** The edge image builds the SPA and records its checksum in the release.

## D8. Passkeys

- **What deployments must do.** The edge's origin must be the configured `rpid` or a subdomain of it, and must be listed in `origins`. For example, `https://login.example.com` with `rpid` `example.com` works.
- **Where the API sits does not matter.** It can be on any private hostname.
- **Enforcement.** The API refuses an `oidc_issuer` its `rpid` does not cover.
- **Existing passkeys.** `rpid` does not change, so they keep working on the hosted pages. Changing `rpid` to fit a new hostname would orphan every existing passkey, and `docs/configuration.md` says so plainly.
- **Deferred.** Related Origin Requests (`/.well-known/webauthn`), for an edge on a different registrable domain.

## D9. `acr` and `amr`

The API derives both from the session's `auth_methods`. The edge only passes them through, and `/oidc/sign` checks them.

`amr` uses the RFC 8176 registry:

| Sign-in method                          | `amr`                                              |
| --------------------------------------- | -------------------------------------------------- |
| Passkey, device-bound (BE flag not set) | `hwk`, plus `user` and `mfa` when UV was performed |
| Passkey, synced or unknown              | `swk`, plus `user` and `mfa` when UV was performed |
| Email code or magic link                | `otp`                                              |
| SMS code                                | `sms`, `otp`                                       |
| TOTP                                    | `otp`                                              |
| Two distinct factors in one session     | `mfa` added                                        |

`acr` uses the OpenID Enhanced Authentication Profile ACR values:

- `phrh` for a device-bound passkey with user verification.
- `phr` for any passkey with user verification.
- Omitted otherwise.

`acr_values_supported` is `["phr", "phrh"]`. Seamless-specific names were rejected, because generic RPs would not recognise them. #510's `webauthn` example is read with this mapping.

## D10. Consent phishing limits

A passkey resists phishing because it is bound to an origin. Two flows can still hand a legitimately authenticated session to an attacker, so they get explicit limits.

**Device flow (#515).** In RFC 8628 the user approves on the real site, but the tokens go to whichever device started the flow (section 5.4).

- The device grant is off for every client by default. It can be enabled only for first-party clients.
- Device-flow tokens never carry `phr` or `phrh` and never satisfy `acr_values` or `max_age` step-up. The passkey proves who approved, not who holds the token.
- User codes live for at most 10 minutes. User code entry is rate limited.
- The approval page says, before any sign-in, "Only continue if you started this on your own device", and names the client.

**Third-party consent.**

- A client is first-party only if an admin marks it so.
- Third-party clients always show the consent page, with their redirect domain.
- An instance-wide `third_party_clients_enabled` flag, off by default, gates them entirely.

## D11. Compatibility and token separation

- **First-party contract unchanged (#509).** First-party access and ephemeral tokens, `/refresh`, `/.well-known/jwks.json`, `aud === ISSUER` and the adapter cookie flow all stay as they are.
- **Provider tokens can never pass as first-party ones.**
  - They carry `iss` equal to `oidc_issuer` (never `ISSUER`) and are signed with provider keys.
  - They carry no first-party `typ` claim.
  - ID tokens have `aud` set to the client id. JWT access tokens have `aud` set to a resource identifier.
  - Access tokens without a resource are opaque and only usable at `userinfo`.

  The first-party verifier rejects all of these.

- **Claims.**
  - `sub` is the user id.
  - Standard `email`, `email_verified`, `phone_number` and `phone_number_verified` follow the requested scopes.
  - `roles` and `org_id` are under a `seamless` scope.
  - `sid` is the provider session id, as the logout specs define it.
  - `acr`, `amr` and `auth_time` follow D9.
  - `client_id` and `scope` appear on JWT access tokens.

  types#118 defines these.

- **Adapter manifest.** It is unchanged in shape. The edge routes are `adapter: false`.

## D12. Admin routes and adapters

- **The routes.** They live on the API, through `defineRoute` with `auth: 'access'` and the admin middleware:
  - `/admin/applications` (create, list, get, update, delete)
  - `/admin/applications/:id/secret` (issue or rotate an opted-in secret)
  - `/admin/applications/:id/keys` (register a JWKS or JWKS URI)
  - `/admin/resources`
  - `/admin/applications/:id/resources`
- **Validation.** They enforce D1's locked configuration, D6 and D10, and audit every change.
- **server#241.** The routes appear in `/.well-known/seamless-adapter.json` as access passthroughs. The JS adapters start proxying admin routes from the manifest instead of hand registration, beginning with these. Step-up and admin role checks stay in the API.
- **Branding** uses the existing system config routes, so dashboard#319 and cli#320 need no new passthrough.
- **Verify-only resource servers** (server#239 and the Go, Python and Rust equivalents) take the issuer URL `oidc_issuer`, fetch the edge's JWKS through discovery, and check `aud`, `scope`, `acr`, `amr` and `auth_time` against types#118.
- **The edge as a dependent.** It is a new Tier 1 dependent of the API (edge routes) and of seamless-auth-server (it builds on `@seamless-auth/express`).

## D13. Rollout

- **The API flag.** `oidc_provider_enabled` in `system_config` defaults to `false`. While it is off, `/oidc/sign`, `/oidc/payloads/*` and the other edge routes answer 404, so main stays releasable for 0.20.x patches while v0.21 lands piece by piece.
- **Always available:**
  - The admin routes for applications and resources.
  - `hosted_ui`.
  - The migrations, including the #414 replay table.

  The console, CLI and types can then be built against main.

- **Adopter opt-in.** Adopters opt in by deploying the edge and setting the flag. The API refuses to turn the flag on unless all of these are true:
  - `oidc_issuer` is set and covered by `rpid` (D8).
  - The `OIDC_JWKS_*` secrets are present.
  - `SEAMLESS_OIDC_SERVICE_TOKEN` is set (D2).
- **Changing the default.** The default may change only when the whole epic is complete and #411 passes against the edge.
- **Managed instances.** Portal and Terraform provisioning gain an edge per instance before the provider is offered there.

## D14. Account notices (#516) and v0.22 webhooks (#418)

The notices endpoint, `POST /applications/account-notices`, stays on the private API, so only the adopter's own backends can reach it.

**Authentication.** A client credentials token from the edge, for the built-in resource `<oidc_issuer>/seamless` with scope `notices:send`. The API verifies it with the provider's public keys.

**Phishing limits.** A notice is sent under the instance's trusted sender, so it is tightly constrained:

- It goes only to a user who already holds a grant with that application.
- The application must have notices enabled by an admin (`oidc_clients`).
- It is plain text only, inside a fixed template the application cannot change: "Sent by <application> through <instance>". It cannot pose as a Seamless security notice.
- An optional action link must be on one of the application's registered redirect origins.
- Rate limits apply per client and per user, and every notice writes an auth event.
- Delivery uses `src/services/accountNotices.ts`, including external delivery (`account_notice_email`, `account_notice_sms`).
- types#120 defines the request and response. The response lists channels, never addresses.

**Relation to #418.** The two are opposite directions on the same application record:

- #516 is the application calling Seamless. It is a command, authorized by an OAuth scope.
- #418 webhooks are Seamless calling the application. They are events, signed by Seamless and delivered to an endpoint registered on the application.

v0.22 adds webhook subscriptions keyed by `oidc_clients`, not a second registry. The auth event a notice writes is one a webhook can later carry. Neither feature depends on the other.

## Inbound OAuth (#413, #414)

- **#413.** Discovery for inbound providers stays in `oauthService.ts` and is unrelated to the edge. An inbound provider configured from an issuer URL fetches that issuer's discovery and JWKS with `jose`.
- **#414.** It uses the replay table in D5.

## Security properties

What this design guarantees, and which parts of it provide each guarantee:

| Property                                                          | Provided by                                                      |
| ----------------------------------------------------------------- | ---------------------------------------------------------------- |
| The auth API is never internet facing                             | D2                                                               |
| Hosted sign-in has every first-party protection                   | D3 (it is first-party sign-in)                                   |
| Edge compromise cannot mint tokens for users not signing in       | D4, plus the edge's own service token (D2)                       |
| Edge compromise cannot raise a session's assurance                | D4, D9                                                           |
| No usable client secret is stored anywhere                        | D6                                                               |
| Revoking a session ends provider access at once                   | D3, D5                                                           |
| Refresh token reuse revokes the grant and the session             | D1 (library reuse detection) plus a revoke of the linked session |
| Sibling subdomains cannot plant cookies or forge requests         | D7                                                               |
| Device flow cannot be used to borrow phishing-resistant assurance | D10                                                              |
| Applications cannot use Seamless's sender to phish                | D14                                                              |
| Provider and first-party tokens cannot be confused                | D4, D11                                                          |

## Consequences

**Benefits**

- The API keeps its private, bearer-only shape.
- Hosted sign-in reuses every existing protection instead of copying it.
- A breach of the public tier is contained.
- `oidc-provider` stays out of the core API.
- Security reviewers (public sector, GovRAMP) get a public tier that holds no user data and no keys.

**Costs**

- Adopters run one more service. Managed instances need one each.
- `/authorize` and `/token` add network hops to the API, which is acceptable at sign-in rates. The edge is unavailable whenever the API is.
- The edge and the API need a compatibility statement and a version check at edge startup.
- Signing in the API depends on `oidc-provider`'s experimental external signing (D4 fallback).
- Some off-the-shelf apps need the opt-in shared-secret mode (D6).
- The OpenID certification is for the edge, so "Seamless Auth is certified" has to name it.
- Most of #405, #406, #409, #411 and #515 moves to the edge repo.

## Issue map

| Issue            | Where                                   | Governed by              |
| ---------------- | --------------------------------------- | ------------------------ |
| #405             | edge, plus API (sign, store)            | D1, D3, D4, D5, D11, D13 |
| #406             | edge, plus API (`hosted_ui`)            | D3, D7, D8               |
| #407             | API                                     | D5, D6, D10, D12         |
| #408             | edge, plus API (reuse revoke)           | D1, D3, D5               |
| #409             | edge (RP-initiated), API (back-channel) | D3                       |
| #410             | edge config, API validation             | D1, D6, D12              |
| #411             | edge CI against the API                 | D1, D13                  |
| #413             | API                                     | Inbound OAuth            |
| #414             | API                                     | D5                       |
| #508             | edge, plus API validation               | D1, D6                   |
| #509             | API (resources), edge                   | D5, D11                  |
| #510             | API (auth context), edge                | D3, D5, D9               |
| #511             | edge                                    | D3, D5                   |
| #515             | edge                                    | D5, D7, D10              |
| #516             | API                                     | D14                      |
| types#97         | types                                   | D5, D6, D12              |
| types#118        | types                                   | D9, D11                  |
| types#120        | types                                   | D14                      |
| server#239       | server                                  | D11, D12                 |
| server#241       | server                                  | D12                      |
| dashboard#296    | dashboard                               | D5, D6, D12              |
| dashboard#319    | dashboard                               | D5 (`hosted_ui`), D7     |
| cli#276, cli#320 | CLI                                     | D5, D6, D12              |
| cli#316          | CLI                                     | D1, D10                  |

The edge repo needs its own tracking issues for the parts that move there, and the edge-to-API route contract (`/oidc/*`) needs a types issue.

## Affected repos

This is a contract-affecting design (new routes, a new token family, a new service). Using the map in `docs/ecosystem.md`:

- **seamless-auth-oidc-provider (new, Tier 1).** The provider, the hosted UI, conformance and certification.
- **seamless-auth-types (Tier 1).**
  - types#97: applications and resources.
  - types#118: claims, discovery, token responses and the step-up challenge.
  - types#120: notices.
  - A new issue for the `/oidc/*` contract.

  Published as 0.34.0 prereleases on `next` until the API settles.

- **seamless-auth-server (Tier 1).**
  - The edge builds on `@seamless-auth/express`, so it needs `__Host-` cookie support if missing, and access to the trusted client context headers.
  - server#241: admin routes followed from the manifest.
  - server#239: verify-only guards against `oidc_issuer`.
- **seamless-auth-js (Tier 1).** The hosted UI builds on it. The SDK contract is unchanged.
- **seamless-messaging (Tier 1).** No change.
- **seamless-auth-admin-dashboard (Tier 2).** Applications page (#296) and branding (#319).
- **seamless-cli (Tier 2).** `seamless apps` (#276), branding (#320), and sign-in through the provider (#316).
- **seamless-templates (Tier 2).** Compose files that add the edge beside the API, with only the edge exposed.
- **seamless-auth-docs (Tier 2).** Provider docs (docs#114, docs#137), the edge deployment model, and the key and secret runbooks.
- **seamless-auth-go, seamless-auth-python, seamless-auth-rust.** The verify-only guards follow D11 and types#118.
- **Portal and Terraform (private).** An edge per managed instance (D13).

## Alternatives considered

- **Provider inside the API, on `/oidc`.** This was the first draft. Rejected because it made the API internet facing, put cookies on it, required copying every first-party protection into the hosted pages, and left signing keys and client secrets on the public tier.
- **Writing our own provider.** Rejected in D1.
- **Signing keys on the edge.** Kept only as the D4 fallback, because it lets a compromised edge mint tokens for any user.
- **`private_key_jwt` only.** Rejected because it would exclude much of the "any OIDC app" long tail. Shared secrets stay off by default instead (D6).
- **Edge with its own database.** Rejected to keep one store of record, owned by the API.
- **Server-rendered hosted pages.** Rejected in favour of a SPA on `@seamless-auth/react`, which reuses the SDK and keeps branding build-free (D7).
- **A table per library model.** Rejected because the library's payload set changes between versions.
