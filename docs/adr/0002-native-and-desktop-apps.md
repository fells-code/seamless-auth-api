# ADR 0002: Native and desktop apps on the OpenID Provider

- **Status:** Proposed
- **Date:** 2026-11-01
- **Builds on:** [ADR 0001](0001-openid-provider.md) (v0.21 OpenID Provider)
- **Issues:** #547, #510, seamless-auth-oidc-provider#34, seamless-auth-oidc-provider#35, seamless-auth-docs#137

## Context

v0.21 made Seamless an OpenID Provider (ADR 0001). The login edge signs users in to any OIDC app, and native public clients with RFC 8252 loopback redirects shipped with it (#508). That covers a desktop app that only needs to know who the user is.

Most desktop apps are more than that. A typical one has its own backend API, for example a note-taking app that syncs to its own service, or a developer tool that calls its vendor's API. The app signs the user in, then calls the backend, and the backend has to trust the call, decide what the user may do, and sometimes reach the user directly. Building that on v0.21 exposed four gaps:

1. **The backend has no way to send account notices to the app's users.** `src/services/applicationNoticeService.ts` sends only to a user who holds a provider grant with the calling client (`hasOidcGrantForUser(user.id, client.id)`). Only a confidential client can get the `client_credentials` token that `POST /applications/account-notices` takes (`checkOidcApplication` in `@seamless-auth/types` refuses `client_credentials` on a public client, and `src/middleware/requireApplicationToken.ts` requires it). Users sign in to the public client, so the backend's confidential client holds no grants and reaches nobody (#547).
2. **The backend cannot see how recently or how strongly the user signed in.** The edge enforces `acr_values` and `max_age` at authorization (`src/authRequirements.ts` in the edge), and the API's `/oidc/sign` already allows and checks `acr`, `amr` and `auth_time` on access tokens (`ALLOWED_CLAIMS.access_token` in `src/services/oidcSigning.ts`). But `oidc-provider`'s JWT access token format does not copy them from the session, and the edge's `providerConfig.ts` sets no `extraTokenClaims`, so RFC 9068 access tokens never carry them (seamless-auth-oidc-provider#34). #510 closed with step-up working at the edge and in ID tokens. Its resource server half is what is left.
3. **Running the edge locally is slow to set up.** It needs HTTPS for its `__Host-` cookies, a hostname under `rpid`, the `OIDC_JWKS_*` keys, `SEAMLESS_OIDC_SERVICE_TOKEN`, an `oidc_issuer` different from `ISSUER`, and the provider flag (seamless-auth-oidc-provider#35).
4. **There is no runnable example of the whole shape.** The native apps guide (`build/native-apps-oidc` in seamless-auth-docs) covers the client side with a CLI. Nothing shows a desktop app, its backend and step-up together (seamless-auth-docs#137).

The goal of this ADR is one general design that lets any desktop app with its own backend work this way, using only what an admin configures in the registry. Nothing here is specific to one product.

Claims about v0.21 below were read in the v0.21.0 source of this repo, the edge (seamless-auth-oidc-provider 0.1.0), `@seamless-auth/types` and seamless-auth-rust 0.4.0. None of the gaps was observed running, and neither was the design below.

## Decision summary

| #   | Decision                                                                                                                                                                       |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| N1  | A desktop app on Seamless is three registry records: a public native client, a confidential backend client and a resource for the backend API.                                 |
| N2  | The desktop app is an RFC 8252 public client. It signs in through the system browser, and asks for an access token for the backend's resource. Shipped in v0.21.               |
| N3  | The backend is a resource server. It verifies RFC 9068 access tokens with a verify-only adapter and never calls the API to check a user token.                                 |
| N4  | An admin links a backend client to the public clients it acts for, in a new `oidc_client_links` table. A link is the only way one client reaches another client's users.       |
| N5  | Account notices honour links (#547). A linked backend sends to users of the public client it names, under that client's name, and D14's limits otherwise stay as they are.     |
| N6  | v0.22 webhooks (#418) reuse links. A subscription on a backend client can carry events about users of the clients it is linked to.                                             |
| N7  | JWT access tokens for a resource carry `acr`, `amr` and `auth_time` from the API's auth context (seamless-auth-oidc-provider#34). Device and client credentials tokens do not. |
| N8  | Step-up between the backend and the app follows RFC 9470: the backend answers `insufficient_user_authentication`, and the app sends the user back through the system browser.  |
| N9  | Tokens live in the OS credential store on the device, the refresh token is used by one process at a time, and the backend's key never ships in the app.                        |
| N10 | Local development is one documented recipe for the API, Postgres and the edge behind local TLS (seamless-auth-oidc-provider#35).                                               |
| N11 | One runnable example covers a desktop app, its backend, a step-up route and a notice, and doubles as a regression check (seamless-auth-docs#137).                              |
| N12 | Domain rules stay with the adopter. Seamless provides identity, assurance, notices and links, and never decides what an app's actions mean.                                    |

## Topology

```
desktop app (public client) ──system browser──► login edge ──► auth API (private)
      │  access token, aud = backend resource         ▲              ▲
      ▼                                               │ JWKS         │ notices (client_credentials,
backend API (resource server) ── verify-only adapter ─┘              │ through a link)
      └──────────────────────────────────────────────────────────────┘
```

- **The desktop app** holds the user's tokens and nothing else. It talks to the edge (sign-in, refresh, revocation) and to its own backend.
- **The backend** verifies user tokens locally against the edge's JWKS. It talks to the auth API only as its own confidential client, for notices.
- **The auth API** stays private, as ADR 0001 D2 requires. Neither the desktop app nor any browser reaches it.

## N1. Three registry records

| Record         | Registry entry                                                                                      | Holds                              |
| -------------- | --------------------------------------------------------------------------------------------------- | ---------------------------------- |
| Desktop app    | `oidc_clients`, `clientType: public`, `tokenEndpointAuthMethod: none`, loopback or private-use URIs | Nothing secret                     |
| Backend client | `oidc_clients`, `clientType: confidential`, `private_key_jwt`, `client_credentials`                 | A private key, on the backend only |
| Backend API    | `oidc_resources`, an absolute URI such as `https://api.example.com`, with its scopes                | Nothing; it names the audience     |

Plus two relations: `oidc_client_resources` lets the desktop app ask for the backend resource and its scopes (shipped, #509), and `oidc_client_links` lets the backend client act for the desktop app (N4, new).

An adopter with a web app beside the desktop app adds a third client (public SPA or confidential web app) and links the same backend client to it. The design does not change with the number of front ends.

## N2. The desktop app is a public native client (shipped)

What v0.21 already does, from #508 and the native apps guide:

- **Registration.** A public client authenticates with PKCE alone. The registry refuses a secret, keys or `client_credentials` on it (`checkOidcApplication`).
- **Redirects.** IPv4 and IPv6 loopback on any port (RFC 8252 section 7.3), private-use schemes in reverse domain form, and claimed `https` URLs. `localhost` is refused. An application with a loopback or private-use redirect is reported as `applicationType: native` (`src/services/oidcApplicationService.ts`).
- **Sign-in.** The app opens the authorization URL in the system browser, never in an embedded webview. Passkeys work there because the hosted page sits under `rpid` (ADR 0001 D8), and an app's own `tauri://`, `app://` or `file://` origin never could.
- **PKCE** with `S256` only, refresh tokens always rotated, revocation at `/token/revocation` (#511).
- **Tokens for the backend.** The app sends `resource=<backend identifier>` and the backend's scopes on the authorization request. The access token is an RFC 9068 JWT with `aud` set to that identifier and `client_id` set to the desktop app (#509, ADR 0001 D11).

Nothing in N2 is new work.

## N3. The backend is a resource server

The backend verifies each user access token itself, with the verify-only guard of a Seamless adapter (server#239 for the JS adapters, and the Go, Python and Rust equivalents). seamless-auth-rust 0.4.0 has a `Verifier` with `require_scope` and `require_step_up` (seamless-auth-rust#15). Each guard must check:

- `iss` equals `oidc_issuer`, found through discovery, and the signature verifies against the edge's `/jwks`.
- The `typ` header is `at+jwt` and `aud` is the backend's resource identifier.
- `scope` covers the route.
- `client_id` is one of the clients the backend expects to serve. Without this check, any client linked to the resource could call the backend. The adopter configures the list, and it usually matches the backend client's links (N4).
- For step-up routes, `acr`, `amr` and `auth_time` (N7, N8).

`sub` is the Seamless user id. The backend maps it to its own records. It never calls `/oidc/*`, introspection or the first-party routes to check a user token, so the auth API can stay private and the backend keeps working through an edge restart for as long as its JWKS cache holds.

Introspection (#511) stays available for an opaque token or a revocation check that cannot wait for the access token to expire. Short access token lifetimes (per client, #539) are the default answer to revocation latency.

## N4. Client links (#547)

A **link** says that a confidential client acts for another client of the same adopter: it is that client's server side. It is the only relationship in the registry that lets one client reach users who signed in to another.

**Storage.** A new table, `oidc_client_links`:

| Column             | Meaning                                                |
| ------------------ | ------------------------------------------------------ |
| `client_id`        | The acting client (the backend). FK to `oidc_clients`. |
| `linked_client_id` | The client it acts for (the desktop app). FK, cascade. |
| `created_at`       | When the link was made.                                |
| `created_by`       | The admin who made it.                                 |

Primary key on (`client_id`, `linked_client_id`), with an index on `linked_client_id` so the console can answer "which backends can reach this app's users". A join table, not a JSONB column on `oidc_clients`, for the same reasons as `oidc_client_resources`: foreign keys, cascading deletes and a reverse lookup.

**Rules.** The admin routes refuse a link unless all of these hold:

- The acting client is confidential. A public client cannot prove who is calling, so it cannot act for anyone.
- The linked client is a different client, and is public. A confidential client already has a server identity and sends its own notices.
- Both are first-party, or both are third-party. A first-party backend never reaches a third-party app's users, and a third-party backend never reaches first-party users. Third-party links also need `third_party_clients_enabled` (ADR 0001 D10).
- Links do not chain. Acting for a client gives no reach to the clients that one is linked to (it has none, being public).

A backend may be linked to several clients (a desktop app and a SPA), and a client may be linked from more than one backend.

**Admin routes.** Following ADR 0001 D12:

- `GET /admin/applications/:id/links`
- `PUT /admin/applications/:id/links/:linkedId`
- `DELETE /admin/applications/:id/links/:linkedId`

Each write takes step-up, is audited (`admin_oidc_application_link_added`, `admin_oidc_application_link_removed`), and appears in the adapter manifest as an access passthrough. Application responses list both directions (`links` and `linkedFrom`) so the console and CLI can show them. types#97's schemas gain the link shape.

**Lifetime.** Disabling or deleting either client ends the link's effect at once, because every check reads the active registry. Revoking a user's grant with the desktop app removes the backend's reach to that user too, because the check is a grant lookup.

## N5. Notices through a link

`POST /applications/account-notices` gains an optional `clientId`, the client the notice is sent for:

- **Absent**, it means the calling client, and behaviour is exactly D14's today.
- **Present**, the calling client must hold a link to it, and the grant check uses it: `hasOidcGrantForUser(user.id, request.clientId)`. A missing link answers the same 404 `notice_unknown_user` as a missing grant, so a client cannot probe the registry.

Everything else in ADR 0001 D14 holds, with these readings:

- **Who may call.** The calling client still needs `client_credentials`, `notices:send` on `<oidc_issuer>/seamless` and `noticesEnabled`. The linked client needs nothing; it cannot call.
- **The template names the client the user knows.** `[<linked client name>] <subject>` and `Sent by <linked client name> through <instance>`. A user who signed in to a desktop app recognises that app, not its backend.
- **Action links.** Today an action link must be on one of the calling client's `https` redirect origins (`registeredOrigins` in `applicationNoticeService.ts`). A native client has none, and a backend client usually has no redirect URIs. So `oidc_clients` gains `noticeActionOrigins`: `https` origins only, never loopback, admin set with step-up and audited. An action link must be on the calling client's `noticeActionOrigins` or `https` redirect origins. This applies to every notice-sending client, linked or not.
- **Rate limits** apply per calling client and per user, as today, so linking to more clients does not raise a backend's budget.
- **Audit.** The auth event records both the calling client and the client the notice was sent for.
- **Contract.** types#120 gains `clientId` on the request. The response is unchanged.

This is the design #547 asks for. ADR 0001 D14's first limit becomes "a user who already holds a grant with that application, or with an application it is linked to", and that ADR gets an amendment when #547 lands.

## N6. Links and v0.22 webhooks (#418)

ADR 0001 D14 put webhook subscriptions on `oidc_clients`. Links extend that without a second registry:

- A webhook endpoint belongs on a backend, so the subscription goes on the backend client.
- A subscription on a client may receive events about users of that client and of the clients it is linked to, with the same first-party rules as N4.
- Each event names the client it concerns, so a backend serving several front ends can tell them apart.

#418 owns the event list, signing and retries. This ADR only fixes that links are the scope rule, so notices (the app calling Seamless) and webhooks (Seamless calling the app) answer "whose users" the same way.

## N7. Step-up claims on access tokens (seamless-auth-oidc-provider#34)

The edge sets `extraTokenClaims` so that a JWT access token for a resource carries the session's `acr`, `amr` and `auth_time` (RFC 9068 section 2.2.1), taken from the same API auth context the ID token uses (`GET /oidc/sessions/:id/auth-context`, ADR 0001 D9).

- **No new trust.** `/oidc/sign` already allows these claims on `access_token` and refuses any value that differs from the session (`oidcSigning.ts`). The edge still cannot raise them.
- **Device grant tokens carry no `acr`** (ADR 0001 D10), after a refresh too.
- **Client credentials tokens carry none of the three.** There is no user.
- **Refresh carries the current values.** A step-up on the session shows on the next access token, as `adoptCurrentAuthContext` already does for the provider session.
- **Introspection returns them** for an active token, so a backend that introspects sees the same values.
- **Opaque access tokens** (no resource) stay usable only at `userinfo` and gain nothing.

This finishes #510's "an API protected by Seamless Auth requires a passkey within the last five minutes for one route" for a resource server that verifies tokens locally. Until it ships, a verify-only `require_step_up` guard sees no `acr` or `auth_time` on any provider access token, so it can only refuse. That follows from the source and was not observed running.

## N8. Step-up between the backend and the app

The backend decides which routes need what, and says so with RFC 9470:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication",
  error_description="A recent passkey sign-in is required", acr_values="phr", max_age=300
```

The desktop app then:

1. Opens the system browser on a new authorization request with the same `resource` and scopes, plus the `acr_values` and `max_age` from the challenge.
2. The hosted page runs `/step-up/*` on the user's existing session (ADR 0001 D3). The API moves the session's auth context, and the edge issues a new code.
3. The app exchanges the code and retries the call with the new access token.

Rules that keep this general:

- **Use registered values.** `phr` and `phrh` (OpenID EAP), and `max_age` in seconds. The edge advertises `acr_values_supported: ["phr", "phrh"]`.
- **Use `max_age` for freshness, `acr` for strength.** A route that needs a passkey within five minutes asks for both.
- **Do not use the device flow for step-up routes.** Its tokens never carry `acr` (N7).
- **Adapters emit the challenge.** Every verify-only guard with `require_step_up`, or its equivalent, answers with this header, and the client SDKs and the example (N11) parse it. seamless-auth-rust 0.4.0 already builds it (`token_guard.rs`).

## N9. Token storage on the device

- **Refresh token** in the OS credential store: the macOS Keychain, Windows Credential Manager, or the Secret Service API on Linux. Never a plain file, an environment variable or the app's own database.
- **Access token** in memory. It is short-lived and cheap to refresh.
- **One refresher at a time.** Refresh tokens rotate, and a token used twice revokes the grant and ends the user's Seamless session (ADR 0001 D1, D3). An app that runs several processes (a tray helper, a CLI, the main window) refreshes through one of them, or behind a lock.
- **Save before use.** Store the rotated refresh token before using the new access token, so a crash cannot leave the app holding a spent one.
- **No backend credential in the app.** The backend client's private key and its `client_credentials` tokens stay on the backend. Anything in the binary can be extracted, which is why the public client has nothing to steal (N2).
- **Sign-out** revokes the refresh token at `/token/revocation`, then deletes it. Ending the Seamless session as well opens the end session URL in the system browser.
- **Sender-constrained tokens** (DPoP, #512) will bind tokens to a key the app holds. When #512 ships, the guide should recommend a non-exportable key in the platform keystore where one exists. Until then, tokens are bearer tokens and the storage rules above are the protection.

## N10. Local development (seamless-auth-oidc-provider#35)

One documented recipe, owned by the edge repo:

- A compose file with the API, Postgres and the edge behind a local TLS proxy with its own CA (for example Caddy's internal CA or mkcert), so `__Host-` cookies and passkeys behave as they do in production.
- Hostnames under one local `rpid`, so the edge's origin sits under it (ADR 0001 D8).
- A seed step that generates the `OIDC_JWKS_*` keys and `SEAMLESS_OIDC_SERVICE_TOKEN`, sets `oidc_issuer`, turns `oidc_provider_enabled` on, and registers the three records of N1 with a link (N4).
- The desktop app needs nothing special locally. Its loopback redirect is the same in development and production, which is a benefit of RFC 8252.

Production checks stay on. The recipe makes them easy to meet locally, and does not relax them. A `seamless` CLI command that runs the same seed is welcome but optional.

## N11. The example and guide (seamless-auth-docs#137)

The native apps guide already covers the client rules, redirects, a CLI, refresh, sign-out and the device flow. #137 adds the rest of this ADR:

- **A runnable example** with a desktop app in one framework (Tauri or Electron), a small backend API using a verify-only adapter, one route that needs `scope` only and one that needs a recent passkey, and a notice sent through a link. It runs on the N10 recipe.
- **A guide section** for the backend: registering the three records, verifying tokens (N3), the step-up challenge (N8), linking and notices (N4, N5).
- **Token storage** as in N9.
- **Kept runnable** in CI against a released API and edge, so it doubles as a regression check for the whole pattern.

## N12. What stays the adopter's job

Seamless provides who the user is, how and when they signed in, a trusted way to reach them, and the registry that says which of the adopter's clients belong together. The adopter decides:

- **Which actions are sensitive**, and which `acr` and `max_age` each needs. Seamless supplies the claims and the challenge, not the policy.
- **What a notice says and when it is sent.** For example, announcing a change at the start of a review period and again before it ends, with a cancel link on the adopter's own site. The schedule, the cancel flow and the state behind them live in the backend.
- **Its own authorization model.** Which `sub` owns which records, and what each scope allows inside the backend. Seamless roles and permissions (v0.22, #415 and #416) can feed it, but the backend enforces it.
- **The `client_id` list each backend accepts** (N3).
- **Keeping the backend's private key safe** and rotating it through `/admin/applications/:id/keys`.

Seamless does not add per-app features for any of these. If two adopters need the same building block, it belongs in a general design like this one.

## Security properties

| Property                                                               | Provided by         |
| ---------------------------------------------------------------------- | ------------------- |
| The desktop app holds no secret worth extracting                       | N2, N9              |
| The auth API stays private; backends verify tokens locally             | N3, ADR 0001 D2     |
| A backend reaches only users of clients an admin linked to it          | N4, N5              |
| A link cannot cross the first-party boundary                           | N4                  |
| Notices still cannot pose as Seamless, and name the app the user knows | N5, ADR 0001 D14    |
| A backend can require a fresh phishing-resistant sign-in per route     | N7, N8              |
| Step-up claims on access tokens cannot be raised by the edge           | N7, ADR 0001 D4, D9 |
| Device flow tokens never satisfy step-up                               | N7, ADR 0001 D10    |

## Consequences

**Benefits**

- Any desktop app with a backend gets sign-in, API protection, step-up and notices from registry configuration alone.
- The same design covers SPAs and mobile apps with a backend, because nothing in N4 to N8 depends on the client being a desktop app.
- Notices and webhooks share one scope rule.

**Costs**

- A new table, three admin routes and a new `oidc_clients` column, plus types#97 and types#120 changes, a console page section and a CLI flag.
- A link is a new way to widen a client's reach, so the console must show it plainly and every change is audited.
- Step-up claims make access tokens slightly larger.
- The example has to be kept running against each release.

## Issue map

| Issue                          | State  | Where      | Must deliver                                                                                        | Governed by |
| ------------------------------ | ------ | ---------- | --------------------------------------------------------------------------------------------------- | ----------- |
| #508                           | closed | API, edge  | Shipped: native public clients, loopback and private-use redirects                                  | N2          |
| #509                           | closed | API, edge  | Shipped: resource-bound JWT access tokens                                                           | N2, N3      |
| #511                           | closed | edge       | Shipped: introspection and revocation                                                               | N3, N9      |
| #510                           | closed | API, edge  | Shipped: step-up at the edge, `acr` and `amr` on ID tokens. Resource server half moves to oidc#34   | N7, N8      |
| #547                           | open   | API, types | `oidc_client_links`, link admin routes, `clientId` on notices, `noticeActionOrigins`, D14 amendment | N4, N5      |
| seamless-auth-oidc-provider#34 | open   | edge       | `acr`, `amr`, `auth_time` on resource access tokens and in introspection, none on device tokens     | N7          |
| seamless-auth-oidc-provider#35 | open   | edge, docs | The local recipe, seeding the three records and a link                                              | N10         |
| seamless-auth-docs#137         | open   | docs       | The runnable desktop and backend example and the backend guide section                              | N11         |
| #418                           | open   | API        | Links as the subscription scope rule                                                                | N6          |
| #512                           | open   | API, edge  | DPoP, then the device key guidance in N9                                                            | N9          |

#547 also needs a types issue for the link shape, `clientId` and `noticeActionOrigins`, and console and CLI issues for managing links. They are opened when #547 starts.

## Affected repos

This is contract-affecting (new admin routes, a new request field, new token claims). Using `docs/ecosystem.md`:

- **seamless-auth-api.** N4, N5.
- **seamless-auth-oidc-provider (Tier 1).** N7 and N10.
- **seamless-auth-types (Tier 1).** Link schemas (types#97), `clientId` on notices (types#120), the access token claims (types#118 already lists them).
- **seamless-auth-server (Tier 1).** The link admin routes as manifest passthroughs. The verify-only guards already check `acr`, `amr` and `auth_time` (server#239).
- **seamless-auth-go, seamless-auth-python, seamless-auth-rust.** No change expected; their step-up guards start passing once N7 ships.
- **seamless-auth-admin-dashboard, seamless-cli (Tier 2).** Managing links and `noticeActionOrigins`.
- **seamless-auth-docs (Tier 2).** N11.

## Alternatives considered

- **Let a public client send notices.** Rejected: a public client cannot authenticate, so anyone who extracts its id could send notices as it.
- **Give the backend client its own grants by signing users in to it.** Rejected: the user would sign in twice, and the backend would need redirect URIs it has no use for.
- **A JSONB `linkedClientIds` column on `oidc_clients`.** Rejected for the reasons in N4: no foreign keys, no cascade, no cheap reverse lookup.
- **An "adopter" or "project" record grouping clients.** Rejected for now: a group would let every member reach every other member's users, which is wider than a backend acting for a front end needs. Links say exactly who acts for whom. A grouping can be built on links later if the console needs one.
- **Send every step-up check to introspection.** Rejected: it puts a network call on every sensitive request, makes the backend depend on the edge being up, and still needs the claims in the introspection response (N7).
- **Domain-specific notice types (scheduled notices, reminders).** Rejected under N12. The backend owns schedules and sends plain notices when it decides to.
