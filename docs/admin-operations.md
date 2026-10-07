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

Auth events cannot be edited or deleted through the application. Each one is hash-chained to the one before it. `GET /admin/auth-events/integrity` verifies the chain and returns its current head, which is worth recording outside the database as part of an evidence package. See [Audit trail integrity](./security-posture.md#audit-trail-integrity).

## Review Accounts

`GET /admin/review-accounts` shows whether store review accounts
([configured by environment variable](./configuration.md#store-review-accounts-optional)) are on,
so a fixed code is not left live after review ends. It takes an `admin`, `admin:read` or
`admin:write` role.

```json
{
  "enabled": true,
  "emails": ["review@example.com"],
  "codeConfigured": true,
  "recentSignIns": {
    "days": 30,
    "count": 4,
    "failedVerifications": 1,
    "lastSignInAt": "2026-10-01T08:00:00.000Z"
  }
}
```

- `enabled` is true when at least one address is listed and `REVIEW_ACCOUNT_CODE` is six letters,
  the same rule that decides whether the fixed code is issued.
- `emails` are the listed addresses, lowercased, each once.
- `codeConfigured` says whether a usable code is set. The code is never returned.
- `recentSignIns` covers the last `days` days (query `days`, 1 to 366, default 30). `count` is
  completed email code sign-ins and verifications by a review address, one per attempt.
  `failedVerifications` is every wrong code entered for one, which matters because the code does
  not rotate. Both are read from auth events flagged with `metadata.reviewAccount: true`, so they
  still report past use after the variables are cleared.

The flag is set on `otp_success`, `otp_failed`, `verify_otp_success` and `verify_otp_failed` for
an address that is issued the fixed code. A listed address with an unusable code gets a random
code and is not flagged. `GET /admin/auth-events` does not filter by metadata, so use this
endpoint, or the audit export, to find the individual events.

## Metrics

The `/internal/auth-events/*` endpoints all accept the same query parameters: `from`, `to`,
`userId`, and `interval` (`hour` or `day`, timeseries only).

`/internal/metrics/dashboard` and `/internal/security/anomalies` take `from` and `to` as well,
with the same validation, and default to the last 24 hours. Both answer with the `window` they
covered.

- **Dashboard metrics.** The `*24h` fields (`loginSuccess24h`, `successRate24h`, and so on)
  always cover the last 24 hours, whatever window is asked for, so a caller never gets a
  different period under the same name. The window-neutral fields beside them (`newUsers`,
  `loginSuccess`, `loginFailed`, `successRate`, `otpUsage`, `passkeyUsage`) cover the
  requested window. `totalUsers`, `activeSessions` and `databaseSize` are current totals.
- **Security anomalies.** Failed and suspicious events in the window, newest first, paged with
  `limit` (at most 200, the default) and `offset`. `total` counts every match in the window,
  not just the page.

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

### Funnel

`GET /internal/metrics/funnel` answers how long the passwordless path takes and how far it is
adopted, over the same `from` and `to` window as the other metrics endpoints (capped at 366
days; `userId` and `interval` are not accepted). With no window it covers all time.

```json
{
  "timeToRegistration": { "count": 412, "medianSeconds": 84.2, "p90Seconds": 260.5 },
  "timeToLogin": { "count": 3188, "medianSeconds": 6.4, "p90Seconds": 41.0 },
  "passkeyAdoption": { "users": 512, "withPasskey": 301, "rate": 0.588 },
  "timeToFirstPasskey": { "count": 301, "medianSeconds": 118.0, "p90Seconds": 86400.0 }
}
```

Every block carries the `count` it was computed over, so a median of three readings is not
read as one of three thousand. Percentiles are `null` when the count is zero.

| Block                | What is measured                                                                                                                                                         |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `timeToRegistration` | Per self-registered account: `user_created` to the first completed sign-in. Accounts created by an administrator or through OAuth sign-up do not emit `user_created`.    |
| `timeToLogin`        | Per attempt: `login_success` to the completed sign-in it led to, within the five minute ephemeral token TTL and before that user's next attempt. OAuth is not included.  |
| `passkeyAdoption`    | Of the accounts created in the window, how many hold at least one passkey. Counted from `credentials` rows, since `registration_success` fires for more than enrollment. |
| `timeToFirstPasskey` | For the accounts that enrolled one: account creation to the first passkey.                                                                                               |

The window applies to where each reading starts (the registration, the attempt, the account
creation), not where it completes, so a registration begun on the last day of the window and
finished the next morning still counts.

### Sign-ins

`GET /internal/metrics/sign-ins` answers how many sign-in attempts succeeded and failed, per
method, device class, mail provider and owner flag, and where attempts stop. It takes the same
`from` and `to` window as the funnel endpoint. The dimensions it groups by are recorded on every
audit row at write time; [docs/telemetry.md](./telemetry.md) describes how each is derived and
why the result can be published.

```json
{
  "deploymentId": "a1b2c3",
  "attempts": { "started": 412, "delivered": 130, "presented": 388, "completed": 371 },
  "signIns": { "success": 371, "failed": 21, "successRate": 0.946 },
  "breakdown": [
    {
      "method": "passkey",
      "deviceClass": "ios",
      "mailProvider": "gmail",
      "owner": false,
      "success": 202,
      "failed": 4
    },
    {
      "method": "magic_link",
      "deviceClass": "windows",
      "mailProvider": "other",
      "owner": true,
      "success": 9,
      "failed": 0
    }
  ]
}
```

The unit is a method presented within an attempt, not an event. Every step taken on one
ephemeral token carries the same `attempt_id`, so a completed OTP sign-in, which writes
`verify_otp_success` twice, counts once, and a person who mistypes a code and then gets it right
counts as one success rather than one failure and one success. A row with no attempt id (written
before the claim existed, or from a magic link opened on another device) stands as its own
attempt.

`breakdown` is one flat row per combination. Pivot on whichever dimension is being reported:
summing `success` and `failed` over `deviceClass` gives the failure rate by platform, over
`mailProvider` gives deliverability, and filtering `owner = false` gives the sign-ins that were
somebody other than the person who set the deployment up. Nothing is pre-aggregated per
dimension, so the same rows answer every question.

`attempts` counts distinct attempt ids, so it covers attempts started since the claim was added.
`delivered` is not a strict step (a passkey attempt goes from `started` to `presented` with
nothing sent). Read `started - presented` as "gave up before proving anything", `delivered -
presented` as "was sent a code or link and never came back", and `presented - completed` as
"tried a factor and it did not work".

## Authentication Coverage Report

`GET /admin/reports/authentication-coverage` answers the question an assessment, an audit
response or a cyber insurance questionnaire asks: how many staff are on phishing-resistant
authentication, is that number going up, and what does the deployment enforce. It takes an
`admin`, `admin:read` or `admin:write` role.

| Query            | Meaning                                                                                        |
| ---------------- | ---------------------------------------------------------------------------------------------- |
| `from`, `to`     | UTC dates (`YYYY-MM-DD`), both included. Default: the 90 days ending today. At most 1827 days. |
| `organizationId` | Scope every figure to the current members of one organization. `404` if it does not exist.     |
| `bucket`         | `month` (default) or `week`, the granularity of `trend`.                                       |
| `format`         | `json` (default) or `csv`.                                                                     |

```json
{
  "period": { "from": "2026-07-09", "to": "2026-10-06" },
  "generatedAt": "2026-10-06T14:02:11.000Z",
  "organizationId": null,
  "bucket": "month",
  "policy": {
    "phishingResistantOnly": false,
    "loginMethods": ["passkey", "email_otp"],
    "passkeyFallbackEnabled": false,
    "authenticator": {
      "attestation": "none",
      "userVerification": "required",
      "attachment": "any",
      "syncedPasskeys": "allow",
      "requireKnownAuthenticator": false,
      "aaguidAllowList": [],
      "aaguidDenyList": []
    }
  },
  "coverage": { "users": 240, "passkeyUsers": 198, "percent": 82.5 },
  "byOrganization": [
    {
      "organizationId": "8d0c...",
      "name": "Public Works",
      "users": 61,
      "passkeyUsers": 58,
      "percent": 95.1
    },
    { "organizationId": null, "name": null, "users": 12, "passkeyUsers": 4, "percent": 33.3 }
  ],
  "trend": [
    {
      "start": "2026-07-09",
      "end": "2026-07-31",
      "users": 231,
      "passkeyUsers": 140,
      "percent": 60.6
    }
  ],
  "authenticatorMix": [
    {
      "aaguid": "fbfc3007-154e-4ecc-8c0b-6e020557d7bd",
      "name": "iCloud Keychain",
      "credentials": 120,
      "users": 117,
      "backupEligible": 120,
      "backedUp": 118
    },
    {
      "aaguid": null,
      "name": null,
      "credentials": 9,
      "users": 9,
      "backupEligible": 0,
      "backedUp": 0
    }
  ],
  "signInMix": {
    "total": 4120,
    "phishingResistant": 3610,
    "percent": 87.6,
    "methods": [{ "method": "passkey", "phishingResistant": true, "signIns": 3610, "users": 196 }]
  }
}
```

### What each figure means

| Block              | What is measured                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `policy`           | What is enforced at `generatedAt`: the login methods `getLoginPolicy()` resolves (passkey only, with fallback off, when `phishing_resistant_only` is on), whether a passkey holder may fall back to another method, and the `authenticator_policy` registration rules. It is the policy now, not the policy across the period.                                                                                                                                                |
| `coverage`         | As of the end of `to`: active users (not revoked) created by then, and how many of them hold at least one WebAuthn credential created by then. A WebAuthn credential is the phishing-resistant credential this server issues; TOTP, codes and magic links are not. `percent` is `passkeyUsers / users`, to one decimal place, and `0` when there are no users.                                                                                                                |
| `byOrganization`   | The same figures per organization, by current membership, sorted by name, then a row with `organizationId: null` for active users in no organization. A user in two organizations is counted in both, so the rows can sum to more than `coverage.users`. With `organizationId` set there is one row and no null row.                                                                                                                                                          |
| `trend`            | One row per calendar month or week (weeks start on Monday, UTC), the first and last clipped to the period. Each row is the coverage as of the end of its bucket, so the last row equals `coverage`.                                                                                                                                                                                                                                                                           |
| `authenticatorMix` | Credentials held by active users at the end of the period, grouped by AAGUID. `aaguid: null` gathers credentials that reported no AAGUID or the all-zero one. `name` comes from a short table of well-known passkey providers, then from the FIDO Metadata Service when it is loaded (only under `attestation: 'direct'`), and is otherwise `null`. `backupEligible` counts credentials whose key can leave the device (synced passkeys); `backedUp` those already backed up. |
| `signInMix`        | Completed sign-ins inside the period, by method. This is the actual side of coverage: a deployment can be at 100% enrollment and still see most sign-ins by email code if fallback is on. Sign-ins are folded by attempt, as on `/internal/metrics/sign-ins`, so an OTP sign-in that writes `verify_otp_success` twice counts once; `users` is distinct users per method. Only `passkey` is phishing resistant.                                                               |

`signInMix.methods` always lists every method, in a fixed order, with zeros where there were
none: `passkey`, `email_otp`, `phone_otp`, `otp`, `magic_link`, `totp`, `oauth`. Code sign-ins
record their channel from this release on; `otp` holds code sign-ins written before that, whose
channel is unknown. A code that completes a registration counts as a sign-in, as it does on the
sign-in metrics.

### Limits

- The trend counts the credentials that exist now, by their creation date. A credential that was
  deleted is gone from `credentials` and cannot be recovered, so a user who enrolled and later
  removed every passkey does not count as covered in any past bucket. The trend can understate
  past coverage; it never overstates it.
- Revocation has no timestamp, so a revoked user is left out of every bucket, including those
  before the revocation. A deleted user is likewise absent from the whole report.
- Organization figures use current membership. Someone who left an organization is not in its
  past buckets, and someone who joined is in all of them.
- `policy` is the configuration when the report was generated. For the history of policy
  changes, read the `system_config_updated` auth events for the period.
- A WebAuthn credential is counted as phishing resistant whatever its attestation. A deployment
  that needs to show only certified authenticators should run `attestation: 'direct'` with
  `requireKnownAuthenticator` or an allow list, which the `policy` block states.

### CSV

`format=csv` returns the same report as `text/csv` with
`Content-Disposition: attachment; filename="authentication-coverage-<from>-to-<to>.csv"`, for
pasting into an assessment or insurance response. It has a header block (period, organization,
generation time), then five sections each introduced by a title line, its own header row and a
blank line before it: enforced policy (setting, value), coverage by organization (with an
`All users` row first and `No organization` last), coverage trend, authenticator mix and
sign-in mix. Lines end in CRLF. Rows are in the same deterministic order as the JSON. A cell
that starts with `=`, `+`, `-` or `@` is prefixed with `'` so a spreadsheet does not evaluate an
organization name as a formula.
