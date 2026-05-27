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
