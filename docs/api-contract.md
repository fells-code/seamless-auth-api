# API Contract: Tokens and Status Codes

This is the reference for what the API returns from each flow: which token comes back where, what
each token carries, and the status codes that callers (and the SDK adapters) branch on. For a
runnable walkthrough, see [direct-http-quickstart.md](./direct-http-quickstart.md); for the token
design rationale, see [architecture.md](./architecture.md#token-model).

## Terminology

- **Identifier** — the value a user logs in with at `POST /login`: either an email or a phone
  number. The request field is `identifier` (not `email`), and the response echoes
  `identifierType: "email" | "phone"`. Endpoints that clearly apply to one channel (for example
  `/otp/generate-login-email-otp`) name that channel explicitly.
- **Ephemeral / access / refresh token** — the three token states below.
- **Service token** — a separate credential presented by a trusted server adapter
  (`x-seamless-service-token`), unrelated to a user session. Not interchangeable with the bearer
  tokens below.

## Which token comes from where

All tokens are returned in the JSON body (the API never sets cookies). Present them as
`Authorization: Bearer <token>`.

| Token         | Issued by                                           | Presented to                                                                         | Purpose                                                | Lifetime                            |
| ------------- | --------------------------------------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------ | ----------------------------------- |
| **Ephemeral** | `POST /login` (and registration start)              | the continuation step (OTP generate/verify, magic-link request/poll, WebAuthn login) | carry a pre-authenticated identity between login steps | short (about 5 minutes)             |
| **Access**    | OTP/WebAuthn/magic-link completion, `POST /refresh` | protected routes (e.g. `GET /users/me`)                                              | authenticated application access                       | `access_token_ttl` (system config)  |
| **Refresh**   | the same completion steps and `POST /refresh`       | `POST /refresh` only                                                                 | obtain a new access token                              | `refresh_token_ttl` (system config) |

### Token shapes

- **Access token** — a signed JWT (RS256). Claims include `sub` (user id), `sid` (session id),
  `iss`, `typ: "access"`, `roles` and `permissions`. In an active organization it also carries
  `org_id`, `org_roles` and `org_permissions`, which apply to that organization only, and any
  custom claims (ADR 0005). The permission claims and custom claims share one 1 KiB budget. When
  they would not fit together, `permissions_omitted: true` replaces `permissions`, `org_roles`
  and `org_permissions`, and absent then means "ask" rather than "none": read the live set from
  `GET /users/me/permissions`. See [Permissions](./admin-operations.md#permissions).
  Verify it against the JWKS at `GET /.well-known/jwks.json`.
- **Ephemeral token** — a signed JWT scoped to the pre-auth step; treat it as opaque. Its `jti`
  is the attempt id every audit row written on the token carries, which is how one sign-in's
  steps are correlated (see [telemetry.md](./telemetry.md)).
- **Refresh token** — an opaque random string (not a JWT), stored server-side only as a hash plus
  a lookup fingerprint. It is **rotated** on every `POST /refresh`: the presented token is
  invalidated and a new one returned, and reusing a retired refresh token revokes the session
  chain. Always persist the newest `refreshToken`.

> `POST /refresh` reads the refresh token from the `Authorization` header, not the request body.

`POST /sessions/exchange` also issues an access and refresh token pair, from a provider sign-in;
see [Native admin tools](#native-admin-tools).

## Status codes to branch on

Most endpoints use conventional codes (`200` success, `400` invalid input, `401`/`403` auth
failures, `500` server error). A few carry branch-significant meaning that clients must handle:

| Endpoint                       | Code  | Meaning                                                                |
| ------------------------------ | ----- | ---------------------------------------------------------------------- |
| `GET /magic-link/check` (poll) | `204` | Not yet verified — keep polling (no body).                             |
| `GET /magic-link/check` (poll) | `200` | Verified — body carries the issued session.                            |
| `GET /magic-link/check` (poll) | `403` | Polling device fingerprint does not match the pending link.            |
| `POST /login`                  | `200` | Returns an ephemeral `token` plus `loginMethods` for this user/device. |
| `POST /login`                  | `423` | The account is locked out. Carries `retryAfterSeconds`.                |
| `POST /refresh`                | `401` | Missing, invalid, expired, or already-rotated refresh token.           |
| `POST /refresh`                | `405` | Method other than POST.                                                |
| `POST /sessions/exchange`      | `400` | `invalid_request`. With `token_already_used`, a replay: see below.     |
| Admin, org and factor routes   | `403` | `step_up_required`, even on a read, for a device-grant child session.  |

The SDK adapters branch on these exact codes (for example, the magic-link poll treats `204` as
"pending"). Changing a branch-significant status code is a contract change; see the ripple
protocol in [ecosystem.md](./ecosystem.md).

### Magic link destination

`GET /magic-link` accepts an optional `redirectUri` query parameter deciding where the emailed
link lands. Omit it and the link keeps the tenant-wide destination, `frontend_url` falling back
to the first configured origin, which is what every existing caller gets.

A supplied value is validated against the configured `origins` the same way
`resolveOAuthRedirectUri` validates an OAuth redirect, and a value outside them answers `400`.
That is what lets one tenant serve a web client and a mobile client without them sharing a
single destination. The token is set as a `token` query parameter on the target, replacing one
of that name the caller had already put there.

A destination that cannot be expressed as an origin, a custom scheme such as `myapp://auth` or a
universal link on a host that is not a WebAuthn origin, goes in the `magic_link_redirect_uris`
system config key instead. Entries there are matched exactly, which is what makes a custom
scheme safe to accept: there is no origin to compare, so only a literal an operator listed is
allowed. The key defaults to `[]`, and an empty list falls back to comparing against `origins`,
so a deployment that sets nothing behaves as described above.

Setting it narrows rather than widens. Once the list is non-empty it is the whole allowlist, and
a destination on a configured origin that is not listed is refused. That is deliberate: a tenant
that needs a mobile scheme should not have to widen `origins`, which gates passkey ceremonies, to
get it.

### Native and mobile clients

Nothing in this contract is browser-specific. A native app completes every flow with the same
routes, either directly against this API or, more usually, through a server adapter running in
bearer transport (`x-seamless-auth-transport: bearer`, `@seamless-auth/express` or
`@seamless-auth/fastify` 0.16 or later), which keeps the adapter's message delivery and client
IP forwarding in the path while the app holds the tokens. What a deployment has to configure:

- **`rpid` and `origins`.** The RP ID is the domain the app's association files are hosted on
  (`apple-app-site-association` with `webcredentials`, `assetlinks.json`), and the web app must
  be same-site with it. iOS reports a passkey's origin as `https://<rpid>`, so that exact
  origin belongs in `origins` even when the web app lives on a subdomain. Android reports
  `android:apk-key-hash:<base64url of the signing certificate's SHA-256>`, which is accepted
  as an opaque URL and must be listed for native passkeys to verify. Keep the web origin first:
  `origins[0]` is the fallback destination for magic links and OAuth.
- **Magic links.** A universal link on the web origin needs nothing extra. A custom scheme goes
  in `magic_link_redirect_uris` (exact match, see above). The app can also skip the link entirely
  and poll `GET /magic-link/check` with the ephemeral token until the session arrives, since
  `/magic-link/verify/:token` completes the link from whichever device opened it.
- **OAuth.** A custom-scheme `redirectUri` is accepted when it is on the provider's
  `redirectUris` allowlist. Some providers refuse custom schemes on a web client type; a
  universal link on the web origin's `/oauth/callback` sidesteps that.
- **Rate limits.** The per-IP flow limits in `flow_rate_limits` are sized for a web audience.
  Raise the `perIp` values for an app behind carrier NAT; see
  [configuration.md](./configuration.md#flow-rate-limits).
- **Session lifetime** is tenant-wide. `refresh_token_ttl` is the absolute lifetime and
  `session_idle_ttl` the idle bound; a phone that is closed for longer than the shorter of the
  two signs out. The absolute lifetime is measured from sign-in and survives refresh, so a
  session that refreshes continuously still ends at it and the user signs in again. The
  `refreshTtl` a refresh returns is what is left of that lifetime, not a fresh full one. There
  is no per-client profile, so a deployment that wants a long-lived mobile session gives every
  client one.
- **Refresh** rotates the refresh token and treats a replay as theft, revoking the whole chain
  with `401 { "error": "refresh_token_reused" }`. A client must refresh once at a time.
- **Authenticator policy.** The defaults (`attestation: "none"`, `syncedPasskeys: "allow"`)
  admit iCloud Keychain and Google Password Manager passkeys. A tenant on
  `syncedPasskeys: "block"` refuses every iOS passkey.

### Native admin tools

A first-party public native client signed in through the OpenID Provider reaches `/admin/*` and
`/users/me` by exchanging the sign-in for a first-party session of its own
([ADR 0003](./adr/0003-native-admin-access.md)). An admin first turns `sessionExchangeEnabled` on
for the client, with `PATCH /admin/applications/:id`. It is off by default, and accepted only on a
first-party public client with a loopback or private-use redirect URI.

**Finding the provider.** An admin names the application with the `oidc_cli_client_id` system
config key, through `PATCH /system-config/admin`. `GET /system-config/public` then answers with:

```json
{
  "loginMethods": ["passkey", "email_otp"],
  "recoveryCodes": true,
  "accountRecovery": false,
  "oidcProvider": { "issuer": "https://login.example.com", "cliClientId": "seamless-cli" }
}
```

`oidcProvider` is sent whole or not at all. It is present only when `oidc_provider_enabled` is on,
`oidc_issuer` and `oidc_cli_client_id` are set, and that application exists, is active and is
eligible for exchange with it turned on. An API that predates the field does not send it either,
so a client must read its absence as "this instance does not advertise" and offer email code
sign-in. Endpoints come from the OIDC discovery document at
`<issuer>/.well-known/openid-configuration`, not from this response. The route is
`Cache-Control: no-store`.

The client runs authorization code with PKCE, or the device grant, with
`resource=<oidc_issuer>/seamless` and `scope=openid session:exchange`, and without
`offline_access`. It then has 60 seconds to send the access token here, directly rather than
through an adapter:

```http
POST /sessions/exchange
Content-Type: application/json

{
  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "subject_token": "<the at+jwt>",
  "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "requested_token_type": "urn:ietf:params:oauth:token-type:refresh_token"
}
```

`requested_token_type` is optional. A `200` is the body `POST /refresh` returns, plus
`issued_token_type`. From there the client uses `/refresh`, `/logout`, `/users/me`,
`/totp/verify-mfa` and `/admin/*` as any first-party client does. `/logout` ends this session and
leaves the browser's alone.

Every failure is a `400` whose `error` is `invalid_request`. A request that fails schema validation
also carries `message` and `details`. Every subject token failure is the bare
`{ "error": "invalid_request" }`, whatever the reason, so the route says nothing about sessions. A
token presented a second time adds `"error_description": "token_already_used"` and revokes the
session the first presentation created, so a client seeing it should sign in again and tell the
user their sign-in may have been intercepted.

**Step-up.** A session from an authorization code grant starts with the parent's step-up as it
stood at the exchange, with the five minute window still running from the original step-up, so a
stale one stays stale. A session from a device grant starts with none. It steps up with the user's own factor:
`POST /totp/verify-mfa`, which is what a CLI uses, or a real passkey assertion on the relying
party's domain through `/step-up/webauthn/*`. Until then it answers `403 step_up_required`, with the
same body as `requireStepUp`, on every route behind `requireAdmin`, on every `/organizations` route
except `POST /organizations/:id/switch`, reads included, whether it acts through a global admin
role or as an ordinary member or owner, and on every route that changes how the account signs in or
recovers: `/totp/enroll/*`, `/totp/disable`, `/webauthn/register/*`, `POST /recovery-codes`,
`DELETE /users/credentials`, `/registration/phone`, `/registration/phone/verify` and
`DELETE /recovery/requests/:id`. `DELETE /sessions/:id`, `DELETE /sessions` and `DELETE /logout/all`
stay open: they gain no access, though they could slow the owner's response. As for any session, a
refresh does not carry a step-up to the new row.

A session from an authorization code grant steps up with a passkey by signing in again with
`acr_values=phr` and `max_age=0`, then exchanging again and logging out the old session. With no
browser session, that records a sign-in and not a step-up, so the command has to run a second
time. It can also use `POST /totp/verify-mfa`.

**A device sign-in with no TOTP cannot enroll one.** The user enrolls from a browser, then signs in
on the device again. Without this, someone who phished a device approval could enroll their own
authenticator and step up with it. A session from an authorization code grant, and every other
first-party session, can enroll as before.

**Lifetime.** The session is capped at its parent's expiry, and `refreshTtl` says what is left. It
ends when its parent does: sign-out at the provider, revocation, expiry or idling out. Refreshing
it keeps the parent from idling out. An expired parent shows up as
`401 invalid_refresh_token` on `POST /refresh`.

**Session lists.** `GET /sessions` and the admin session views add `parentSessionId`,
`exchangeClientId` and `exchangeGrantType` to a child, and leave them out otherwise.

### Error body

Every `4xx` and `5xx` response uses one shape, with one additive extension for schema
validation failures covered below:

```json
{ "error": "User already exists", "message": "optional extra detail" }
```

- **`error`** is always present and carries the human-readable reason. Read this field.
- **`message`** is optional extra detail. It is never a substitute for `error`, so a consumer
  never has to check two fields to find out why a call failed.

Some handlers used to return `{ message }` with no `error`, which left the shape ambiguous. They
now all set `error`. `tests/unit/routes/errorShapeCoverage.spec.ts` walks every registered route
and fails if any failure response declares a schema without a required `error` string, so a new
route cannot reintroduce the split.

A `429` from the rate limiters is included. It used to be the one exception, answering plain text
because express-rate-limit sends a string message through `res.send`, and it is now
`{ "error": "Too many requests, please try again later" }` like everything else. The limiters are
middleware rather than route handlers, so nothing a handler declares would mention them;
`defineRoute` declares the `429`, and the `500` from the top-level error handler, on every route
it registers, so both appear in the OpenAPI document and in a client generated from it.

`ErrorSchema` in [`src/schemas/generic.responses.ts`](../src/schemas/generic.responses.ts) is the
canonical definition. `InternalErrorSchema` is a deprecated alias of it and is identical on the
wire.

#### Schema validation failures

A request that fails its route's `params`, `query` or `body` schema is refused by
`defineRoute` before the handler runs, and answers with the same shape plus a `details` list
naming the fields that were rejected:

```json
{
  "error": "invalid_request",
  "message": "Request failed schema validation.",
  "details": { "issues": [{ "path": ["attachment"], "code": "invalid_value", "message": "..." }] }
}
```

`error` is the stable code `invalid_request`, so a client branches on that rather than on prose.
`details` is additive: a consumer reading only `error` is unaffected. Issues are mapped field by
field rather than passed through from the validator, so the response names which field was wrong
without echoing back the value that was sent.

`ValidationErrorSchema` is the definition, and `defineRoute` declares it as the `400` for any
route that validates a request, so the documented response matches what validation actually
returns. A route that already declares a richer `400` of its own, such as
`AdminValidationErrorSchema`, keeps it.

Success responses are unaffected: `{ "message": "Success" }` on a `200` is a success payload, not
an error body, and clients that branch on it keep working.

## A note on login responses

`POST /login` answers `200` with an ephemeral `token` and `loginMethods` for every identifier it
accepts, whether or not an account exists. An identifier with no usable account gets a **decoy**
token: real, signed, and indistinguishable from one issued to a genuine account. Every endpoint
that accepts a pre-auth token answers for a decoy the way it answers for a real one, so the
continuation steps do not disclose it either.

**`POST /login` no longer returns `401`.** A client that branched on `401` to mean "no such user"
will now follow the normal continuation flow instead, and the failure will surface at the
continuation step (a wrong OTP, an assertion that cannot verify) rather than at login. That is the
point: there is no longer an answer to give.

What still distinguishes an account: a `423` lockout, which only a real account can be in, and a
`400` for a malformed identifier, which does not depend on whether an account exists.

See [security-posture.md](./security-posture.md) for the full design, including how a decoy subject
is derived and what remains observable.
