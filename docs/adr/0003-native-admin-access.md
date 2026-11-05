# ADR 0003: Admin API access for native clients signed in through the OpenID Provider

- **Status:** Accepted
- **Date:** 2026-11-04
- **Builds on:** [ADR 0001](0001-openid-provider.md) (D3, D4, D10, D11, D14), [ADR 0002](0002-native-and-desktop-apps.md) (N2, N7, N9)
- **Issues:** #544, part of epic #551 (native apps), unblocks seamless-cli#316

## Context

seamless-cli#316 signs the CLI in through the OpenID Provider: authorization code with PKCE and a loopback redirect (RFC 8252 section 7.3), and the device authorization grant (RFC 8628) on a headless machine. That brings passkey sign-in to the CLI. But the CLI exists to call the API. Its instance commands (`users`, `config`, `org`, `sessions`, `clients`, `resources`, `whoami`) call `/admin/*` and `/users/me`, and today they authenticate with a first-party session from email code sign-in.

Three facts about the current code decide the shape of the answer:

- **Admin routes take a first-party access token and nothing else.** Every `/admin/*` route is `auth: 'access'`, then `requireAdmin('read' | 'write')`, and most admin writes add `requireStepUp()` (`src/routes/admin.routes.ts`). `verifyBearerAuth` calls `validateBearerToken`, which accepts only a first-party JWT (`iss` and `aud` equal to `ISSUER`, a first-party `typ`) whose `sessions` row is live (`src/services/sessionService.ts`). ADR 0001 D11 makes sure a provider token never passes that check.
- **Step-up is state on a `sessions` row.** `requireStepUp` reads `stepUpVerifiedAt` on the caller's session and accepts it for five minutes (`DEFAULT_STEP_UP_MAX_AGE_SECONDS` in `src/services/stepUpService.ts`). `/step-up/webauthn/*` and `/totp/verify-mfa` write it. A passkey step-up needs a WebAuthn ceremony on an origin under `rpid`, which a terminal cannot run. TOTP needs only a code, so the authenticator app is the one step-up a CLI can do by itself.
- **A provider sign-in is a first-party session the edge holds.** The edge signs the user in through the first-party routes, keeps that session's access and refresh tokens in its own `__Host-` cookie, and binds the provider grant to the row's id (D3, `bindOidcSession` in `src/services/oidcPayloadStore.ts`). For the device grant, that row is the session of the browser that approved the code, often on another machine. `/oidc/sign` knows the session and the grant type of every token it signs (`checkUserToken` in `src/services/oidcSigning.ts`), and refuses `acr`, `amr` and `auth_time` on device-grant tokens (D10).

So a CLI signed in through the edge holds tokens the API refuses for everything it does, and admin step-up cannot see the passkey it signed in with. This ADR chooses how a native client signed in through the provider reaches the admin API. It is written for the CLI but applies to any first-party native admin tool.

Claims about current behaviour were read in this repo at `main` (after #567) and the edge at 0702bce. None of the designs below was built or observed running.

## Options

### Option A: an admin scope on RFC 9068 access tokens

The CLI asks the edge for an access token for the built-in resource `<oidc_issuer>/seamless` (D14) with new scopes `admin:read` and `admin:write`. `/admin/*` and `/users/me` accept that token as a second auth mode beside `access`: verified with the provider JWKS, `typ: at+jwt`, `aud` the built-in resource, `sub` a user (not the client, which would be a client credentials token). The CLI refreshes at the edge. First-party tokens are unchanged.

### Option B: token exchange into the same session

As the issue words it. The CLI presents a provider access token at an RFC 8693 style exchange route on the API and gets back a first-party access and refresh token pair bound to the same `sessions` row as the provider sign-in. The CLI then uses the first-party contract as it does today.

### Option C: token exchange into a linked child session (new)

The same exchange as B, with one change: the API mints a **new** first-party session for the CLI, linked to the provider sign-in's session as its parent, instead of handing out the parent itself. The subject token is a dedicated, single-use, 60 second token for the built-in resource, recorded when the API signs it. The child session has its own refresh chain and its own step-up state, ends when its parent ends, and copies the parent's assurance only when the grant was not the device grant.

B looks simpler than C but does not work on the current model, for three reasons:

1. **One row, two holders.** A `sessions` row has one `refreshTokenLookup` and rotates into a new row on every refresh (`replacedBySessionId`). The edge's adapter already holds that row's refresh token. A second refresh token for the same row either needs a second chain on one row, which the model does not have, or makes the CLI and the edge rotate one chain, which the reuse detection in `refreshSession` treats as theft and revokes, signing the browser out.
2. **Step-up leaks across devices.** For a device sign-in, the row is the approving browser's session. If the CLI shares it, `requireStepUp` reads the browser's `stepUpVerifiedAt` for the CLI, which is exactly the borrowing D10 forbids. In reverse, a TOTP step-up in the CLI would elevate the browser session.
3. **Logout couples the wrong things.** `seamless profile logout` would end the user's browser session, and an admin revoking "the CLI" would revoke the browser too.

C keeps everything B is for (the CLI ends up on the first-party contract it already speaks) and removes all three.

## The questions in #544, per option

### Replay: how a stolen provider token is kept from being reused

|                                         | A                                                                                                                                                   | B                                                                         | C                                                                                                                                             |
| --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| What a thief steals                     | The admin-scoped access token, presented on every call, and the CLI's provider refresh token                                                        | The subject token in flight, then a first-party refresh token             | The 60 second subject token in flight, then a first-party refresh token                                                                       |
| Lifetime                                | The resource's access token lifetime (edge default 600 seconds, `DEFAULT_ACCESS_TOKEN_TTL`), reusable for all of it                                 | Whatever access token lifetime the subject has, reusable until it expires | At most 120 seconds, enforced by `/oidc/sign`; the edge sets 60                                                                               |
| Single use                              | No. A bearer access token is reusable by design                                                                                                     | Possible only by adding a consumed-token record                           | Yes. Recorded at signing, consumed atomically at the exchange. A second presentation is refused and revokes the session the first one created |
| Sender constraint (RFC 9449)            | Strongest once #512 lands: the edge binds tokens with `cnf.jkt` (section 6.1) and the API checks a proof on every admin call (sections 4.3 and 7.1) | Only the exchange hop                                                     | Only the exchange hop: when #512 lands, the API checks that the proof key's thumbprint equals the subject token's `cnf.jkt`                   |
| What protects the long-lived credential | Rotation and reuse detection at the edge (RFC 9700 section 2.2.2)                                                                                   | Broken: see reason 1 above                                                | Rotation and reuse detection on the child's own first-party chain (RFC 9700 section 2.2.2), the OS keychain (N9)                              |

A has one real advantage here: with DPoP, every admin call is sender constrained. C's first-party refresh token is a bearer credential in the keychain, which is exactly what the CLI holds today after email code sign-in. C does not make the steady state worse than today, but A could make it better once #512 ships. First-party DPoP is the way C gets there later (see Alternatives).

### Audience and scope

|                             | A                                                                                                                                                                                                 | B and C                                                                                                                                                                                                                                                               |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `aud`                       | `<oidc_issuer>/seamless`                                                                                                                                                                          | `<oidc_issuer>/seamless` on the subject token. The issued tokens are first-party (`aud` equal to `ISSUER`)                                                                                                                                                            |
| Scope                       | `admin:read`, `admin:write`                                                                                                                                                                       | One scope, `session:exchange`, alone on the token                                                                                                                                                                                                                     |
| What keeps other tokens out | The admin mode checks `iss`, `typ`, `aud` and scope (RFC 9068 section 4), and `sub` not equal to `client_id`. Roles still come from the database, so a scope is a ceiling, never a grant of admin | The exchange checks the same, plus a signing record that only exists for tokens the API signed for this purpose. A token minted for any other resource, which a third-party backend could have received, has the wrong `aud` and no record, so it cannot be exchanged |
| Who may get one             | First-party clients an admin allows the admin scopes                                                                                                                                              | First-party public native clients an admin turns `sessionExchangeEnabled` on for                                                                                                                                                                                      |

Restricting the subject token to the built-in resource and a dedicated scope matters most. RFC 8693 leaves the validity criteria for a subject token to the authorization server (section 2.1), and its security considerations defer to the general OAuth guidance (section 5). Accepting any provider access token would let every resource server that ever receives one turn it into a session. Under C, the subject token is useful nowhere else, so nobody else ever holds one.

### Step-up carry-over (`acr`, `auth_time`, and the device grant)

**Option A.** `requireStepUp` would read `acr` and `auth_time` from the token (RFC 9068 section 2.2.1, RFC 9470 section 6.1) instead of the row. That needs seamless-auth-oidc-provider#34 (N7) first, because the edge does not put them on access tokens today. A loopback CLI steps up by running a new authorization request with `acr_values=phr` and `max_age` (RFC 9470 section 4). The device grant has no answer. Device-grant tokens never carry the claims (D10), and TOTP step-up never earns an `acr` (`recordStepUpVerification` moves `authTime` only when the method earns at least the session's `acr`), so a TOTP step-up cannot be expressed on a provider token at all. Making it work needs new per-grant step-up state that the edge would read when it signs, which is a second step-up system beside the first-party one.

**Option B.** Shares the parent row's state, so a device sign-in inherits the approving browser's step-up. Refused by D10.

**Option C.** The child session has its own step-up state, and `requireStepUp` is unchanged.

- **At the exchange, for an authorization code grant,** the child copies the parent's `authMethods`, `authTime`, `stepUpVerifiedAt` and `stepUpMethod` as they are at that instant. The API reads them from the parent row, the same source `/oidc/sign` already treats as the truth (D4, D9), so it does not depend on oidc#34. The five minute window still runs from the original step-up time, so a stale step-up stays stale. Later step-ups on either session never flow to the other.
- **For a device grant,** the child copies nothing. It starts with no auth methods and no step-up, as D10 requires: the passkey proved who approved, not who holds the token (RFC 8628 section 5.4).
- **A loopback CLI steps up with a passkey** by running a new loopback authorization with `acr_values=phr` and `max_age=300`. The hosted page runs `/step-up/*` on the parent (D3), the CLI exchanges the fresh subject token for a new child session with a fresh step-up, and logs out the old child. It can also use TOTP.
- **A device sign-in steps up with the authenticator app only,** through the existing `/totp/verify-mfa` on its own child session. A user with no TOTP enrolled cannot do admin writes from a device sign-in. That is a deliberate limit, not a gap: any passkey path for a headless machine would hand a browser's assurance to whoever holds the device code, which is the attack D10 exists to stop.
- **A device sign-in also needs step-up before admin reads** (decision X7). RFC 8628 section 5.4 describes an attacker who starts a device flow and gets a real user to approve it. Write step-up already stops that attacker from changing anything, because they cannot produce the victim's TOTP code. Without X7 they could still list every user on the instance.

### Revocation

| Event                                                            | A                                                                                                                           | C                                                                                                                                                                                                                                                                        |
| ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| User logs out at the edge (RP-initiated) or signs out everywhere | The parent row is revoked (D3). The admin mode checks the session on every call, so the next call is refused                | The parent is revoked and the revocation cascades to its children. A read-time parent check refuses the child even if a cascade was missed                                                                                                                               |
| CLI logs out                                                     | Revokes its provider refresh token at the edge (RFC 7009 section 2.1). The parent browser session stays                     | `/logout` revokes the child only, as today. The browser session stays                                                                                                                                                                                                    |
| Admin revokes a session or the user                              | Revoking the parent ends the token at its next call                                                                         | Revoking the child ends only the CLI. Revoking the parent, or `sessionsRevokedBefore`, ends both. Both appear in session lists, the child labelled with its client and grant                                                                                             |
| Refresh token reuse                                              | At the edge: the library revokes the grant and the API revokes the linked session (D1, D3), which signs the browser out too | On the child chain: `revokeSessionChain` on the child only, since the stolen credential is the CLI's. At the edge: as for A, and the parent's revocation cascades to the child                                                                                           |
| Back-channel logout                                              | The CLI has no back-channel endpoint, and does not need one: its tokens die with the session                                | The same. When the parent ends, the API sends logout tokens to the RPs holding grants on it (D3, OIDC Back-Channel Logout 1.0 section 2.5). The child ends with it, as section 2.7 asks for refresh tokens issued without `offline_access` to a session being logged out |
| Client disabled, or `sessionExchangeEnabled` turned off          | The edge stops issuing; tokens already issued live until they expire unless the admin mode also checks the client per call  | Revokes every child session the client exchanged for, at once                                                                                                                                                                                                            |

B has no usable revocation story: every event above that should end the CLI's access also ends the browser's, and the reverse.

## Against the three promises

| Promise               | A                                                                                                                                                                                                                                                                            | C                                                                                                                                                                                                                                                                |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Most secure**       | Per-call sender constraint once #512 ships. But the most sensitive surface in the API gains a second token family and a second auth mode, with roles, recovery restriction, org context and step-up each implemented twice. Device sign-ins cannot step up without new state | One token family on admin routes. D10 is enforced structurally, because a device child never has assurance to borrow. Replay is closed by audience, scope, a two minute lifetime and single use. The steady-state credential is a bearer refresh token, as today |
| **Safe**              | Honest only after oidc#34 ships, because until then step-up silently fails for every provider token                                                                                                                                                                          | Nothing existing changes: first-party tokens, `/refresh`, step-up and every adapter are untouched. Email code sign-in stays the fallback. Exchange is off per client by default, and turning it off revokes what it produced, so it is reversible                |
| **Easy to integrate** | The CLI keeps a second token family, refreshes at the edge instead of `/refresh`, and learns a new step-up flow. Every future native admin tool repeats that                                                                                                                 | One extra POST after a standard OAuth flow. From then on the CLI runs the code it already has for `/refresh`, `/logout`, `/totp/verify-mfa`, `/admin/*` and `/users/me`                                                                                          |

**Recommendation: Option C.** It keeps the admin surface on one token family that the API alone issues and checks, it is the only option that answers the device grant's step-up without new machinery, and it is the smallest change for the CLI. It gives up A's per-call DPoP, which is not available today either way, and the path to it (first-party DPoP) is open.

## Decision summary

| #   | Decision                                                                                                                                                                                                     |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| X1  | Native clients reach the admin API through a token exchange into a linked child first-party session (Option C). Admin routes keep `auth: 'access'` only, and D11 stands.                                     |
| X2  | The subject token is an RFC 9068 access token for `<oidc_issuer>/seamless` carrying only `session:exchange`, at most 120 seconds long, for a first-party public native client with `sessionExchangeEnabled`. |
| X3  | `/oidc/sign` records every `session:exchange` token it signs, and `POST /sessions/exchange` consumes that record once. A replay is refused and revokes the session the first use created.                    |
| X4  | The child session has its own refresh chain and step-up state, is bounded by its parent's lifetime, and ends whenever its parent ends.                                                                       |
| X5  | For an authorization code grant, the child copies the parent's auth context and step-up state at the exchange. For a device grant, it copies nothing.                                                        |
| X6  | A device-grant child steps up with TOTP only. A loopback child steps up with a passkey by signing in again with `acr_values` and `max_age` and exchanging again, or with TOTP.                               |
| X7  | A device-grant child needs a fresh step-up before any `/admin/*` route, reads included.                                                                                                                      |
| X8  | The edge never completes an authorization for an exchange-enabled client without user interaction, even with a live browser session.                                                                         |
| X9  | When #512 ships, the exchange verifies a DPoP proof against the subject token's `cnf.jkt`, and exchange-enabled clients can be set to require it.                                                            |

## X2. The subject token

- **Requested** with `resource=<oidc_issuer>/seamless` (RFC 8707) and `scope=openid session:exchange`, on the authorization request or the device authorization request.
- **Allowed** by the registry only for a client that is first-party, public and native (`applicationType: native`, from a loopback or private-use redirect, N2), and that an admin has turned `sessionExchangeEnabled` on for. `getOidcClientResources` adds the built-in resource with that one scope and `accessTokenTtlSeconds: 60` for such a client, the way it adds `notices:send` for a notices client. The edge already takes the lifetime from that list (`resourceServers.ts`).
- **Signed** only when the token's scope is exactly `session:exchange`, `aud` is a single string equal to the built-in resource, `jti` is present and `exp - iat` is at most 120. A client credentials token can never carry the scope.
- **No refresh token.** The CLI does not ask for `offline_access`, so the only long-lived credential it ends up with is the first-party one.

## X3. Signing record and single use

When `/oidc/sign` signs a `session:exchange` token, it writes an `oidc_payloads` row: `model: 'SessionExchangeToken'`, `id` the `jti`, `session_id` the sign request's session, `payload` with the client id, user id and grant type, and `expires_at` the token's `exp`. The table, its `consumed_at` column and its purge job already exist (D5).

This one record answers three things the token itself cannot:

- **Which session it came from.** Provider access tokens carry no first-party session id.
- **Which grant produced it.** Missing `acr` does not mean device grant: an email code sign-in has no `acr` either. The record states it.
- **Whether it was used.** The exchange sets `consumed_at` in one conditional update, so two concurrent presentations cannot both win, the same reasoning as `claimSessionRotation`.

## X4 to X7. The exchange and the child session

`POST /sessions/exchange` takes RFC 8693 parameter names (section 2.1) in the API's JSON body style:

```json
{
  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "subject_token": "<the at+jwt>",
  "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "requested_token_type": "urn:ietf:params:oauth:token-type:refresh_token"
}
```

It answers with the same session response `/refresh` returns, so the CLI parses nothing new, plus `issued_token_type` (section 2.2.1). Errors follow section 2.2.2: `invalid_request` for a malformed request and for every subject token failure, with one body for all token failures so the route cannot be used to probe sessions. A replayed token adds `error_description: "token_already_used"`, which tells the legitimate client something only it and a thief can know.

The API exchanges only when all of these hold:

- The token verifies against the provider JWKS with `iss` equal to `oidc_issuer`, `typ: at+jwt`, `aud` the built-in resource, scope exactly `session:exchange`, and `sub` not equal to `client_id`.
- Its signing record exists, is unconsumed, and names the same user and client as the token.
- The client is still active, first-party, public, and has `sessionExchangeEnabled`.
- The parent session, resolved forward through rotation (`resolveCurrentSession`), is live, belongs to `sub`, and is not a recovery session.

The child session is an ordinary `sessions` row with three new columns, carried forward on every rotation: `parentSessionId`, `exchangeClientId` and `exchangeGrantType`. Its `organizationId` comes from the parent. Its absolute expiry is at most the parent's.

- **Validity.** `validateSessionRecord` and the refresh path refuse a child whose parent no longer resolves to a live session. The cascade on revoke keeps session lists accurate, and the read-time check makes a missed cascade harmless.
- **Activity.** A child refresh counts as activity on the parent, as a provider token signed for the parent already does (`recordProviderActivity`, D3). Without that, an active CLI would be signed out when the browser session idles out.
- **Assurance (X5).** Copied from the parent at the exchange for `authorization_code`, never for `urn:ietf:params:oauth:grant-type:device_code`.
- **Device children (X7).** `requireAdmin` refuses a child with `exchangeGrantType` set to the device grant unless its step-up is fresh, with the existing `403 step_up_required` body, so the CLI's handling is one code path.
- **Audit.** `session_exchanged` (client, grant, parent), `session_exchange_replayed`, and the existing session events for the child.

## X8. No silent authorization for exchange-enabled clients

Any program on a machine can send an authorization request with the CLI's client id and its own loopback port. RFC 8252 section 8.6 says an authorization server should not process authorization requests automatically, without user consent or interaction, unless the client's identity can be assured, and names claimed `https` redirects as acceptable proof. A loopback redirect is not: any local program can open a loopback port and receive the code. The edge skips consent for first-party clients (D7), so a user with a live browser session would otherwise be signed in to a local impersonator with no prompt, and the exchange would turn that into an admin session.

So for an exchange-enabled client, the edge always shows a confirmation that names the client and the account, even with a live session, and the hosted page cannot be framed (D7's CSP). The device grant already has its own warning page (D10).

## What seamless-cli#316 builds against

1. **Discover.** Read `oidc_issuer` from the instance and fetch `<oidc_issuer>/.well-known/openid-configuration`. With no provider, keep email code sign-in.
2. **Sign in, loopback.** Authorization code with PKCE `S256` (RFC 8252 section 8.1), redirect to `http://127.0.0.1:<port>/callback` (section 7.3), `resource=<oidc_issuer>/seamless`, `scope=openid session:exchange`, no `offline_access`. The user confirms in the browser (X8).
3. **Sign in, `--device`.** The device authorization request with the same `resource` and `scope` (RFC 8628 section 3.1), then poll the token endpoint (sections 3.4 and 3.5).
4. **Exchange at once.** `POST <instanceUrl>/sessions/exchange` with the access token, within its 60 seconds. Store the returned first-party tokens in the OS keychain, as today. Keep no provider token.
5. **Use the API as today.** `/refresh`, `/logout`, `/users/me`, `/admin/*` and `/totp/verify-mfa` are unchanged.
6. **Step up on `403 step_up_required`.**
   - Loopback session: offer a passkey (repeat step 2 with `acr_values=phr` and `max_age=300`, exchange, swap the keychain tokens, `/logout` the old child) or the authenticator app.
   - Device session: offer the authenticator app only, and say why when TOTP is not enrolled.
7. **On `invalid_request` from the exchange,** sign in again. If the description is `token_already_used`, tell the user their sign-in may have been intercepted.

The CLI's e2e covers both paths against a v0.23 API and edge.

## API work breakdown

1. **Migration.** `sessions` gains `parentSessionId` (nullable, FK to `sessions`), `exchangeClientId` and `exchangeGrantType`, carried forward on rotation. `oidc_clients` gains `sessionExchangeEnabled` (default `false`).
2. **Registry and admin routes.** The application admin routes accept `sessionExchangeEnabled` only on a first-party public native client, with step-up and an `admin_oidc_application_session_exchange_updated` event. Turning it off or disabling the client revokes its exchanged sessions. `getOidcClientResources` adds the built-in resource with `session:exchange` and a 60 second lifetime for such clients. Follow-ups in seamless-auth-types (types#97 shape), the dashboard and `seamless apps`.
3. **`/oidc/sign`.** The X2 checks, and the X3 signing record.
4. **`POST /sessions/exchange`.** `defineRoute` with `adapter: false` (native clients call it directly, adapters never proxy it), request and response schemas, a per-IP rate limit, the checks above, child session issuance through `sessionService`, the X5 copy, audit events. Regenerate `openapi.json` and `adapter-manifest.json`.
5. **Session lifecycle.** The parent check in `validateSessionRecord` and the refresh path, the lifetime cap, parent activity on child refresh, and the cascade from every revoke path (logout, admin revoke, sign out everywhere, chain revocation, concurrent session eviction).
6. **Device children.** The X7 check in `requireAdmin`.
7. **Session lists.** `/sessions` and the admin session views show a child's client and grant. A types change.
8. **Docs.** An amendment to ADR 0001 D11 naming `/sessions/exchange` as the one place a provider token is accepted, and only to mint a first-party session. `docs/architecture.md`, `docs/api-contract.md` and the native apps guide.
9. **Tests.** Replay (sequential and concurrent), wrong `aud`, extra scope, expired record, disabled client, recovery parent, device child step-up, and each revoke path ending the child.

Edge work: X8, and DPoP on the exchange hop with #512 (X9).

## Decisions confirmed

The maintainer accepted option C on 2026-11-04, with the settings this record recommends: bearer first-party tokens on admin calls until first-party DPoP exists, X4 (the child's lifetime is tied to its parent and child refreshes count as parent activity), X5 (a loopback exchange inherits the parent's step-up from the last five minutes), X7 (device grant sessions need a fresh step-up before any admin call), X8 (no silent authorization for exchange-enabled clients), the names `session:exchange`, `POST /sessions/exchange` and `sessionExchangeEnabled`, and the narrow amendment to ADR 0001 D11.

## Security properties

| Property                                                                                 | Provided by      |
| ---------------------------------------------------------------------------------------- | ---------------- |
| Admin routes accept one token family, issued and checked only by the API                 | X1, ADR 0001 D11 |
| A provider token for any other resource cannot become a session                          | X2, X3           |
| A subject token works once, for at most two minutes, and a replay is detected            | X2, X3           |
| Device sign-ins never borrow the approving browser's assurance                           | X5, ADR 0001 D10 |
| A phished device approval cannot read or change admin data without the user's own factor | X6, X7           |
| Ending the provider sign-in ends the CLI's admin access at once                          | X4               |
| Ending the CLI's session does not end the user's browser session                         | X4               |
| A local program cannot silently obtain an admin session through the CLI's client id      | X8               |

## Consequences

**Benefits**

- The CLI, and any later native admin tool, reaches the admin API with passkey sign-in and keeps its existing first-party code.
- No change to `/admin/*`, `requireStepUp`, first-party tokens, adapters or the adapter manifest's shape.
- Exchanged sessions are visible and revocable like any other session.

**Costs**

- Three `sessions` columns, one client flag, one route and a signing record, plus a read-time parent lookup on every request from an exchanged session.
- A narrow, documented exception to D11: one route accepts a provider token, to mint a first-party session.
- Until first-party DPoP exists, the CLI's refresh token is a bearer credential, as it is today.
- Device sign-ins without TOTP can read nothing on `/admin/*` (X7) and must use the loopback flow or email code sign-in.

## Issue map

| Issue                          | Where     | Must deliver                                                        | Governed by     |
| ------------------------------ | --------- | ------------------------------------------------------------------- | --------------- |
| #544                           | API       | This ADR                                                            | All             |
| new API issue                  | API       | Work breakdown items 1 to 9                                         | X1 to X7        |
| new edge issue                 | edge      | Confirmation page for exchange-enabled clients                      | X8              |
| #512                           | API, edge | DPoP, then the exchange's proof check                               | X9              |
| seamless-auth-oidc-provider#34 | edge      | Not required by this design. Still needed for resource servers (N7) | N7              |
| seamless-cli#316               | CLI       | The flow in "What seamless-cli#316 builds against"                  | X2, X6, X8      |
| types#97                       | types     | `sessionExchangeEnabled`, session origin fields                     | X4, work item 7 |

## Affected repos

This is contract-affecting (a new route, a new client field, new session fields in responses, a new scope on the built-in resource). Using `docs/ecosystem.md`:

- **seamless-auth-api.** Everything in the work breakdown.
- **seamless-auth-oidc-provider (Tier 1).** X8, and X9 after #512. The 60 second lifetime comes from the API's resource list with no edge change.
- **seamless-auth-types (Tier 1).** The client flag, the exchange request and response, and session origin fields.
- **seamless-auth-server, seamless-auth-js (Tier 1).** No change. The route is `adapter: false`.
- **seamless-cli, seamless-auth-admin-dashboard (Tier 2).** #316, the flag in `seamless apps` and on the applications page, and the session origin in session lists.
- **seamless-auth-docs (Tier 2).** The native apps guide gains admin tools.

## Alternatives considered

- **Option A, an admin scope on provider access tokens.** Rejected for X1. Its per-call DPoP is real but not available yet, and it costs a second auth mode on every admin route and a second step-up system for device sign-ins.
- **Option B, exchange into the same session.** Rejected for the three reasons under Options.
- **Exchange at the edge's token endpoint, as a custom grant.** It would keep the CLI talking only to the edge and reuse the edge's DPoP when #512 lands. Rejected: the edge would gain a service route that mints first-party sessions, which widens what a compromised edge can do (D4), and the CLI already reaches the API for every command it runs.
- **Accept any provider access token at the exchange.** Rejected under X2: it turns every resource server that receives a token into a possible session thief.
- **Seed the child's step-up from the token's `acr` and `auth_time`.** Rejected for now: it waits on oidc#34, and the parent row is the same source of truth one step earlier. Worth revisiting if exchange ever accepts tokens the API did not record.
- **First-party DPoP now.** Out of scope. It is the way to sender-constrain the CLI's long-lived credential, and belongs with #512 as its own decision.
- **Keep email code sign-in for admin tools.** Rejected: it keeps admin access on a phishable factor, which is what #316 exists to end. It stays as the fallback.
