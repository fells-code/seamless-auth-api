# Admin Operations

Seamless Auth API includes administrative endpoints for self-hosted operators. Admin access is controlled by scoped roles and should be used from a trusted operator surface.

## Scoped Admin Roles

Admin routes are split by intent:

- Read routes accept `admin`, `admin:read`, or `admin:write`.
- Write routes accept `admin` or `admin:write`.
- `admin:write` satisfies `admin:read`.
- `admin:read` does not satisfy write checks.

The legacy `admin` role remains broad for backwards compatibility.

### Making scoped roles assignable

Enforcement understands scoped roles, but a role can only be handed out if it appears in
`available_roles`, which is what `GET /roles` returns and what the console's role picker offers.
Ship `admin:read` and `admin:write` there so read-only admin can be granted without typing a raw
role string:

```text
AVAILABLE_ROLES=user,admin,admin:read,admin:write
```

`AVAILABLE_ROLES` seeds `available_roles` on first boot only. On an instance that is already
running, add the scoped roles through the admin system-config endpoints instead, since the stored
row is authoritative from then on. See
[Environment vs system_config](./configuration.md#environment-vs-system_config).

### Assignment is validated

`POST /admin/users` and `PATCH /admin/users/:userId` reject any role that is not in
`available_roles` with `400 Invalid roles`, naming the offending roles in `details.roles`.

This exists because enforcement never matches an unlisted role. Before validation, a typo like
`admin:reed` or `admin:readonly` was stored happily, granted nothing, and reported no error, so
the mistake only surfaced later as an admin who could not do anything.

The match is exact. Listing `admin:write` does not make `admin:write:users` assignable, and
wildcards like `admin:*` have to be listed explicitly to be handed out, even though enforcement
understands them.

If `available_roles` is empty or unreadable, validation is skipped rather than rejecting every
assignment. It is a guardrail against typos, not an access control, so failing open there cannot
grant access that enforcement would not already refuse.

### The owner grant

A user who signs up with a configured `OWNER_EMAIL` is granted `admin:write` on account creation,
not `admin:read`. This is deliberate: the owner paid for the instance and has to be able to run
it, including granting admin to teammates. Read-only would leave a freshly provisioned tenant with
no one able to administer it.

Instances whose `available_roles` predates scoped roles and lists only `admin` get `admin`
instead, which is equivalent in power, so the grant never silently becomes a no-op.

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
