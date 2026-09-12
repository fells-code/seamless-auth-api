# Auth path telemetry

Every `auth_events` row carries five dimensions, recorded when the row is written because none
of them can be recovered later: the mail provider is taken from an address the row does not
store, the device class from a user agent that only means something once the adapter forwards
the browser's, and the attempt id from a token claim. A sign-in that happens before the
dimensions exist is a reading thrown away.

They exist so that one query can answer "how many logins, across how many deployments, at what
success rate", broken down by mail provider and device class, and so that the answer can be
published. A fleet of real deployments reporting operational numbers is the argument to a
technical buyer who does not believe managed auth marketing, and it is only an argument if the
numbers can be shown.

## The dimensions

| Column          | Value                                                                                                         | Set from                                                                                             |
| --------------- | ------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `deployment_id` | `APP_ID`                                                                                                      | The environment, on every row. The same value as `sessions.infraId`.                                 |
| `device_class`  | `ios`, `android`, `macos`, `windows`, `linux`, `chromeos`, `bot`, `unknown`                                   | The request user agent, on every row.                                                                |
| `mail_provider` | `gmail`, `outlook`, `yahoo`, `icloud`, `proton`, `aol`, `fastmail`, `gmx`, `zoho`, `yandex`, `other`, or null | The subject's address, when the row is about the request principal or the handler names the subject. |
| `owner`         | `true`, `false`, or null                                                                                      | Whether the subject's address is in `OWNER_EMAIL`. Null when the subject is unknown.                 |
| `attempt_id`    | UUID or null                                                                                                  | The ephemeral token's `jti`, on every row written on that token.                                     |

### Device class

Platform families rather than form factors, because platform is where passkeys differ. iCloud
Keychain, Google Password Manager, Windows Hello and a Linux desktop with no platform
authenticator are four different passkey experiences, and "mobile" against "desktop" would hide
the two that matter most. The mobile split still falls out of it.

`bot` separates scanners (crawlers, `curl`, HTTP client libraries, headless browsers) from
people, so a scanner's failures do not sink a published success rate. `unknown` is a missing
user agent or one that names no platform. A server runtime such as `node` is `unknown`, not
`bot`: it is what the adapter sends when it calls on a browser's behalf without forwarding the
browser's user agent, and those are real people.

The classifier reads the user agent string and nothing else. An iPad in desktop mode reports
itself as a Mac and is counted as one.

### Mail provider

A fixed list of consumer providers plus `other`, never the domain. The domain is an address for
anyone on a family or small business domain, and the rows are meant to be published. Regional
variants (`yahoo.co.uk`, `hotmail.fr`) match their provider on the leftmost label.

The cost is that a custom domain hosted on Google Workspace or Microsoft 365 lands in `other`,
since telling those apart takes an MX lookup on the send path. `other` is therefore "not a
consumer mailbox", which is still the split that matters for deliverability: consumer providers
are where a message goes to spam.

### Owner

`OWNER_EMAIL` is the address a managed instance grants admin to at signup. The flag is what
makes "did somebody other than the owner sign in during week four" a query rather than a
guess. It is computed at write time against the environment, so a later change to
`OWNER_EMAIL` does not rewrite history.

Null and false are different: null means the row does not know who the subject is (a decoy
continuation, an administrator acting on another account), false means a known non-owner.
Count the second, not the absence of the first.

### Attempt

`/login` and `/registration/register` each start an attempt: they mint an id, write it on the
row that records the start (`login_success` or `user_created`), and sign the ephemeral token
with it as the `jti`. The bearer middleware reads the claim back on every later request, and
`AuthEventService` writes it on every row from that request, so an attempt's steps correlate
exactly rather than by adjacency in time. A step that re-mints the token mid-flow, such as an
OTP resend, passes the id it received on so the attempt stays whole.

OAuth attempts carry no id: `oauth_login_started` has no account and no token. A magic link
opened on a second device carries none on the `magic_link_success` it writes there, since that
route is unauthenticated; the polling device's `magic_link_poll_completed_successfully` does.

## What the adapter has to forward

The adapter is the only client this API sees, so without help every row carries the adapter's
own address and user agent. `x-seamless-client-ip` already carries the address. The user agent
travels the same way:

```
x-seamless-client-user-agent: <the browser's User-Agent>
```

Both are honoured only alongside a valid `x-seamless-service-token`, since either would
otherwise let any caller choose its audit identity. The forwarded user agent replaces the
request header in place, so the audit row, the session record and the magic link device binding
all see the browser's without knowing the substitution happened. An adapter that does not
forward it produces `device_class = 'unknown'` on every row, and the breakdown by device class
says nothing until it does.

## Deliverability

A send is `otp_success` (with `metadata.channel` saying `email` or `sms`) or
`magic_link_requested`, carrying the recipient's provider. A send the provider refused is
`otp_failed` or `magic_link_failed` with `reason: 'Delivery failed'`, carrying the same. A
message that was accepted and never arrived leaves no synchronous trace, which is the failure
mode people actually fear, so deliverability by provider is read as sends against completions:
`otp_success` rows for a provider against `verify_otp_success` rows for it, `magic_link_requested`
against `magic_link_poll_completed_successfully`.

## The query

Per deployment, `GET /internal/metrics/sign-ins` runs it (see
[admin-operations.md](./admin-operations.md#sign-ins)). Across a fleet, the same shape over
rows collected from every deployment:

```sql
WITH presented AS (
  SELECT deployment_id,
         COALESCE(attempt_id::text, id::text) AS attempt,
         CASE
           WHEN type LIKE 'webauthn_login%' THEN 'passkey'
           WHEN type LIKE 'verify_otp%'     THEN 'otp'
           WHEN type LIKE 'magic_link%'     THEN 'magic_link'
           WHEN type LIKE 'oauth_login%'    THEN 'oauth'
           WHEN type LIKE 'totp%'           THEN 'totp'
         END AS method,
         device_class,
         mail_provider,
         owner,
         BOOL_OR(type IN (
           'webauthn_login_success', 'verify_otp_success',
           'magic_link_poll_completed_successfully', 'oauth_login_success', 'totp_success'
         )) AS succeeded
  FROM auth_events
  WHERE type IN (
    'webauthn_login_success', 'verify_otp_success', 'magic_link_poll_completed_successfully',
    'oauth_login_success', 'totp_success',
    'webauthn_login_failed', 'verify_otp_failed', 'magic_link_failed',
    'oauth_login_failed', 'totp_failed'
  )
  GROUP BY 1, 2, 3, 4, 5, 6
)
SELECT method,
       device_class,
       mail_provider,
       COUNT(DISTINCT deployment_id)             AS deployments,
       COUNT(*) FILTER (WHERE succeeded)         AS success,
       COUNT(*) FILTER (WHERE NOT succeeded)     AS failed
FROM presented
WHERE owner = false
GROUP BY 1, 2, 3
ORDER BY 1, 2, 3;
```

The `owner = false` filter is what makes it a number about other people. The week-four
question is the same rows with `deployment_id` in the `GROUP BY` and a `created_at` window
placed four weeks after each deployment's first row.

## Publishability

Every column is coarse by construction. `device_class` is one of eight words, `mail_provider`
one of eleven, `owner` a bit, and `deployment_id` an opaque generation id that names no
person. A row still carries `user_id`, `ip_address` and `user_agent`, as every audit row does,
so the row is not the published artifact. The published artifact is the output of the query
above, which carries none of them: counts per method, device class and provider, and how many
deployments they came from.

That is the whole of the decision. Publish aggregates, never rows, and keep the dimensions
coarse enough that an aggregate over one deployment does not describe one person. A breakdown
cell with a count of one describes one person by definition, so a published table suppresses
cells below a floor.

## Retention

The dimensions add nothing to a row that would need a different retention from the rest of it,
so they follow whatever `auth_events` retention becomes
([issue #173](https://github.com/fells-code/seamless-auth-api/issues/173)), which today is
indefinite. What leaves a deployment is the aggregate, which names nobody and can be kept for
as long as the comparison is interesting. Do not export rows to a central store as a substitute
for the aggregate: that would recreate the retention question in a second place with weaker
controls, and the aggregate already answers every question the rows were recorded to answer.

## What it does not measure

- A regenerated Seamless Idea application is a new `APP_ID`, a new database and so a new
  deployment. Fleet counts are of deployments as they were built, not applications as a person
  thinks of them.
- Rows written before the columns existed have every dimension null and no attempt id. They
  still count once each in the breakdown; they do not count in `attempts`.
- `other` does not separate a Google Workspace domain from a self-hosted one.
- An iPad in desktop mode is `macos`. A browser that lies about its platform is believed.
