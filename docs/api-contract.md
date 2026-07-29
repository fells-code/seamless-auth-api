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

| Token         | Issued by                                           | Presented to                                                         | Purpose                                                | Lifetime                            |
| ------------- | --------------------------------------------------- | -------------------------------------------------------------------- | ------------------------------------------------------ | ----------------------------------- |
| **Ephemeral** | `POST /login` (and registration start)              | the continuation step (OTP generate/verify, magic-link request/poll) | carry a pre-authenticated identity between login steps | short (about 5 minutes)             |
| **Access**    | OTP/WebAuthn/magic-link completion, `POST /refresh` | protected routes (e.g. `GET /users/me`)                              | authenticated application access                       | `access_token_ttl` (system config)  |
| **Refresh**   | the same completion steps and `POST /refresh`       | `POST /refresh` only                                                 | obtain a new access token                              | `refresh_token_ttl` (system config) |

### Token shapes

- **Access token** — a signed JWT (RS256). Claims include `sub` (user id), `sid` (session id),
  `iss`, `typ: "access"`, `roles`, and `org_id` when the session has an active organization.
  Verify it against the JWKS at `GET /.well-known/jwks.json`.
- **Ephemeral token** — a signed JWT scoped to the pre-auth step; treat it as opaque.
- **Refresh token** — an opaque random string (not a JWT), stored server-side only as a hash plus
  a lookup fingerprint. It is **rotated** on every `POST /refresh`: the presented token is
  invalidated and a new one returned, and reusing a retired refresh token revokes the session
  chain. Always persist the newest `refreshToken`.

> `POST /refresh` reads the refresh token from the `Authorization` header, not the request body.

## Status codes to branch on

Most endpoints use conventional codes (`200` success, `400` invalid input, `401`/`403` auth
failures, `500` server error). A few carry branch-significant meaning that clients must handle:

| Endpoint                       | Code  | Meaning                                                                |
| ------------------------------ | ----- | ---------------------------------------------------------------------- |
| `GET /magic-link/check` (poll) | `204` | Not yet verified — keep polling (no body).                             |
| `GET /magic-link/check` (poll) | `200` | Verified — body carries the issued session.                            |
| `GET /magic-link/check` (poll) | `403` | Polling device fingerprint does not match the pending link.            |
| `POST /login`                  | `200` | Returns an ephemeral `token` plus `loginMethods` for this user/device. |
| `POST /login`                  | `401` | Unknown or unverified identifier (see the enumeration note below).     |
| `POST /refresh`                | `401` | Missing, invalid, expired, or already-rotated refresh token.           |
| `POST /refresh`                | `405` | Method other than POST.                                                |

The SDK adapters branch on these exact codes (for example, the magic-link poll treats `204` as
"pending"). Changing a branch-significant status code is a contract change; see the ripple
protocol in [ecosystem.md](./ecosystem.md).

### Error body

Every `4xx` and `5xx` response uses one shape:

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

`ErrorSchema` in [`src/schemas/generic.responses.ts`](../src/schemas/generic.responses.ts) is the
canonical definition. `InternalErrorSchema` is a deprecated alias of it and is identical on the
wire.

Success responses are unaffected: `{ "message": "Success" }` on a `200` is a success payload, not
an error body, and clients that branch on it keep working.

## A note on login responses

`POST /login` returns different content for a known-and-verified user (an ephemeral token plus
`loginMethods`) than for an unknown or unverified identifier (a `401`). This makes some user
enumeration possible, which is partly inherent to passwordless login where the client must learn
which continuation methods are available. The intended posture is tracked as a follow-up; do not
rely on the current exact shapes for unknown identifiers.
