# Admin Operations

Seamless Auth API includes administrative endpoints for self-hosted operators. Admin access is controlled by scoped roles and should be used from a trusted operator surface.

## Scoped Admin Roles

Admin routes are split by intent:

- Read routes accept `admin`, `admin:read`, or `admin:write`.
- Write routes accept `admin` or `admin:write`.
- `admin:write` satisfies `admin:read`.
- `admin:read` does not satisfy write checks.

The legacy `admin` role remains broad for backwards compatibility.

## Device Replacement Recovery

Administrators with write access can prepare an account for device replacement:

```http
POST /admin/users/:userId/recovery/device-replacement
```

The endpoint requires a fresh step-up session. By default it:

- revokes active sessions
- removes passkeys
- disables enabled TOTP credentials

The response returns counts only:

```json
{
  "userId": "user-id",
  "revokedSessions": 2,
  "removedCredentials": 1,
  "disabledTotpCredentials": 1
}
```

It does not return credential private material, TOTP secrets, recovery codes, refresh tokens, or PRF output.

## Session Hygiene

Administrative session endpoints can list sessions and revoke individual or all sessions for a user. Use these endpoints when responding to suspicious account activity or user-requested device cleanup.

## Lockout Policy

`lockout_policy` controls account lockout for identified users after repeated failed login attempts:

```json
{
  "enabled": true,
  "maxFailures": 10,
  "windowSeconds": 900,
  "lockoutSeconds": 900
}
```

Lockout is checked after a user has been identified. Keep route-level and destination-aware limits enabled for unknown identifiers and delivery abuse.

## Audit Events

Admin actions are recorded as auth events with redacted metadata. Do not store raw secrets, tokens, OTPs, magic-link URLs, PRF values, account keys, or provider tokens in admin metadata.

## Metrics

The `/internal/auth-events/*` endpoints all accept the same query parameters: `from`, `to`,
`userId`, and `interval` (`hour` or `day`, timeseries only).

### Date windows

`from` and `to` are parsed as dates and rejected with `400` when unparseable or inverted. The
window is also capped by the bucket size it would be rendered at, so an hourly series cannot be
asked for a year of buckets:

| `interval` | Maximum window |
| ---------- | -------------- |
| `hour`     | 31 days        |
| `day`      | 366 days       |

A window with `from` but no `to` runs to the current time and is measured the same way, so
`?from=2020-01-01` is rejected rather than silently truncated.

`/auth-events/timeseries` returns one bucket per interval across the requested window. With no
window it falls back to the last 24 hourly buckets, or the last 30 daily buckets for
`interval=day`.

### Categories

Auth event types are rolled up into mutually exclusive categories, so the counts in a summary sum
to the total number of events:

`suspicious`, `login`, `registration`, `webauthn`, `oauth`, `magicLink`, `otp`, `totp`, `stepUp`,
`token`, `system`, `other`.

`suspicious` is matched first, so a security signal lands in one bucket rather than being split
across the surface it came from. Everything else is matched on the event-type prefix, which keeps
`webauthn_login_success` in `webauthn` rather than `login`.

`/auth-events/grouped` returns these categories in `summary`, plus an `outcomes` roll-up
(`success`, `failed`, `suspicious`, `other`) derived from the event-type suffix.

Each `/auth-events/timeseries` bucket carries `total` and a `categories` map alongside `success`
and `failed`. Those two stay login-only for backwards compatibility with existing dashboards; use
`categories` for OTP, WebAuthn, magic link, and OAuth activity.
