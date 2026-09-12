---
'seamless-auth-api': minor
---

Instrument the auth path: every `auth_events` row now carries the dimensions the passwordless
claim is measured along, and `GET /internal/metrics/sign-ins` reports sign-in outcomes by them.

Five columns are added to `auth_events`, recorded at write time because none can be
backfilled. `deployment_id` is `APP_ID`, so rows collected across a fleet stay attributable.
`device_class` folds the user agent into a platform family (`ios`, `android`, `macos`,
`windows`, `linux`, `chromeos`, `bot`, `unknown`), since platform is where passkeys differ.
`mail_provider` folds the subject's address into a consumer provider or `other`, never the
domain, so the rows can be published. `owner` records whether the subject is in `OWNER_EMAIL`,
which is what makes "did somebody other than the owner sign in" a query. `attempt_id` is the
ephemeral token's new `jti`: `/login` and `/registration/register` mint it, write it on the row
that starts the attempt, and every step taken on the token carries it, so one sign-in's steps
correlate exactly rather than by adjacency in time. `user_agent` widens to `text` at the same
time, since a real browser user agent could exceed the old 255 character column and fail the
whole audit write.

Deliverability is now recorded on both ends of a send. Every OTP send is one `otp_success` row
with `metadata.channel` (`email` or `sms`), including the send registration makes, which used
to write none. A send the provider refuses is a new `otp_failed` event with
`reason: 'Delivery failed'`, distinguished from a server fault by a typed `DeliveryError`.

The adapter can now forward the browser's user agent as `x-seamless-client-user-agent`, honoured
under the same service-token rule as `x-seamless-client-ip`. Without it every row records the
adapter's own user agent and the device class breakdown reads `unknown`. The middleware that
applied the trusted address is renamed `applyTrustedClientContext`.

`GET /internal/metrics/sign-ins` answers, over a `from` and `to` window, how many attempts
succeeded and failed per method, device class, mail provider and owner flag, plus where attempts
stop (`started`, `delivered`, `presented`, `completed`). It counts a method presented within an
attempt rather than an event, so a completed OTP sign-in, which logs `verify_otp_success`
twice, counts once. Behind `admin:read`, like the funnel endpoint.

`docs/telemetry.md` records how each dimension is derived, the fleet-wide form of the query,
and the publishability and retention decision: aggregates are what leave a deployment, never
rows, and the dimensions follow whatever `auth_events` retention becomes.
