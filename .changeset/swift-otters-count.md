---
'seamless-auth-api': minor
---

Fix a third set of defects found in a review of `src`.

**`extraFields` cannot overwrite the session it is added to.** The optional bag added in
0.9.0 was spread after every session field, so a flow passing `token`, `refreshToken` or
`sub` would have replaced the real value in the response. Only the OAuth callback passes it,
and only `returnTo`, so nothing was wrong at runtime; the shape invited it. It is spread
first now, and the session fields always win.

**Login success rates count sign-ins.** `login_success` is what the pre-auth step emits once
it has resolved which methods an identifier may use, before any factor is presented, so a
rate built from it reported the share of identifiers that resolved to a usable account as
though it were the share of people who got in. `/internal/auth-events/login-stats` and the
dashboard's `successRate24h` now count the events that mean somebody finished signing in, and
the two sets are typed as `AuthEventType`, so a member renamed upstream is a compile error
rather than a silently empty bucket.

**The event timeseries classifies every outcome.** Its `success` and `failed` counters
matched the two login literals, leaving every passkey, OAuth, magic link and OTP outcome out
of a pair sitting beside a `total` that included them. They go through `authEventOutcome`,
which the grouped summary in the same file already used.

**OAuth provider edits are serialised.** Each one read the whole provider array through the
process-cached config, edited it in memory and wrote all of it back, so two administrators
adding a provider at once silently dropped one, and an instance holding a five minute old
cache could overwrite an addition made through another. The row is now read inside the
transaction with `FOR UPDATE`, and the duplicate and not-found checks run on that locked
value rather than on a cached copy.

**An organization and its owner membership are created together.** They were two untransacted
writes, and a failure between them left an organization nobody is a member of: access is
granted through membership and nothing deletes an organization, so the row was unreachable
and unremovable.

**A policy that turns attestation on after startup takes effect.** The FIDO metadata service
initialised once at boot, so enabling it later gave half a policy: credentials that could not
be traced to a manufacturer were still refused, but the lookup that refuses a model the blob
does not list never ran. Registration now brings the service up for the policy in force,
throttled so an unreachable blob does not turn every registration into an outbound request.

**The related-device lookup is bounded.** `/admin/users/:userId/anomalies` read every
`auth_events` row a user had ever produced to derive their distinct addresses and agents, then
turned those into an `IN` list of the same unbounded size, which a long-lived account can push
past the bind-parameter ceiling. It reads recent activity and caps the identifiers.

**Membership values are deduplicated before the cap.** Slicing to fifty first let repeats
consume the whole allowance and silently discard a distinct scope behind them.
