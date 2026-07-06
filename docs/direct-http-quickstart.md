# Direct HTTP Quickstart

This walks through a full passwordless login with plain `curl`, without the SeamlessAuth SDKs.
It is the "Direct HTTP APIs (advanced)" path: you call this API directly and take custody of the
returned tokens yourself. For browser apps, the recommended path is a trusted server adapter that
holds token custody for you (see [Deployment Topology](./architecture.md#deployment-topology)).

The example uses **email OTP** because it is the easiest flow to drive from a shell. The same
shape applies to phone OTP (swap `email` for `phone` endpoints).

Assumptions:

- The API is running at `http://localhost:5312`.
- `email_otp` is in `LOGIN_METHODS`.
- A verified user already exists for `alice@example.com`. To create one from scratch, use
  `POST /registration/register` followed by `POST /otp/verify-email-otp` (same token shape as
  steps 3-4 below).

Set a base URL for the snippets:

```bash
BASE=http://localhost:5312
```

## 1. Start a login

`POST /login` with an identifier (email or phone). It returns a short-lived **ephemeral token**
plus the login methods allowed for this user and device.

```bash
curl -sS -X POST "$BASE/login" \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"alice@example.com"}'
```

```json
{
  "message": "Login continued",
  "token": "<EPHEMERAL_TOKEN>",
  "sub": "user-uuid",
  "identifierType": "email",
  "loginMethods": ["email_otp", "passkey"],
  "ttl": 300
}
```

Capture the ephemeral token:

```bash
EPHEMERAL=<EPHEMERAL_TOKEN>
```

## 2. Request the login OTP

`GET /otp/generate-login-email-otp` with the ephemeral token as a Bearer credential sends the code
to the user's email.

To read the code back in a headless flow, add `x-seamless-auth-delivery-mode: external`. In
development this returns the code directly in a `delivery` payload. **In production, external
delivery also requires a valid `x-seamless-service-token` from a trusted server adapter**; without
it the code is only sent through the configured messaging provider.

```bash
curl -sS "$BASE/otp/generate-login-email-otp" \
  -H "Authorization: Bearer $EPHEMERAL" \
  -H 'x-seamless-auth-delivery-mode: external'
```

```json
{
  "message": "OTP sent",
  "delivery": { "kind": "otp_email", "to": "alice@example.com", "token": "ABCDEF" }
}
```

Without external delivery mode, the response is just `{ "message": "OTP sent" }` and you read the
code from the email itself.

## 3. Verify the OTP and receive tokens

`POST /otp/verify-login-email-otp` with the ephemeral token as the Bearer credential and the code
in the body. On success it returns the **access token** and **refresh token**.

```bash
curl -sS -X POST "$BASE/otp/verify-login-email-otp" \
  -H "Authorization: Bearer $EPHEMERAL" \
  -H 'Content-Type: application/json' \
  -d '{"verificationToken":"ABCDEF"}'
```

```json
{
  "message": "Login successful",
  "token": "<ACCESS_TOKEN>",
  "refreshToken": "<REFRESH_TOKEN>",
  "sub": "user-uuid",
  "roles": ["user"],
  "email": "alice@example.com",
  "ttl": 1800,
  "refreshTtl": 3600
}
```

```bash
ACCESS=<ACCESS_TOKEN>
REFRESH=<REFRESH_TOKEN>
```

## 4. Call an authenticated endpoint

Present the access token as a Bearer credential.

```bash
curl -sS "$BASE/users/me" -H "Authorization: Bearer $ACCESS"
```

```json
{
  "user": {
    "id": "user-uuid",
    "email": "alice@example.com",
    "phone": null,
    "roles": ["user"]
  },
  "credentials": []
}
```

## 5. Refresh the session

`POST /refresh` takes the **refresh token in the `Authorization` header** (not the body) and
returns a new access token and a new refresh token.

```bash
curl -sS -X POST "$BASE/refresh" -H "Authorization: Bearer $REFRESH"
```

```json
{
  "message": "Token refreshed",
  "token": "<NEW_ACCESS_TOKEN>",
  "refreshToken": "<NEW_REFRESH_TOKEN>",
  "sub": "user-uuid",
  "ttl": 1800,
  "refreshTtl": 3600
}
```

Refresh tokens are **rotated**: the token you just sent is invalidated and replaced by the new
one. Reusing an old refresh token is treated as a compromise signal and revokes the session chain,
so always store the newest `refreshToken` from each refresh.

## Token custody notes

- The access token is a signed JWT; verify it against the JWKS at
  `GET /.well-known/jwks.json` (RS256).
- This API returns tokens only in JSON bodies and never sets cookies. In a browser context, keep
  the refresh token out of JavaScript-accessible storage by terminating the session in a trusted
  server adapter or backend instead of integrating directly. See
  [Deployment Topology](./architecture.md#deployment-topology).
