# Security Posture

Decisions that are deliberate tradeoffs rather than open bugs. Each one states what the server
does, why, and what would change it. If you are looking for how to configure the server, see
[configuration.md](./configuration.md); for operational hardening, see
[production-operations.md](./production-operations.md).

## User enumeration on `/login`

**Posture: partially mitigated, deliberately.** A failed `/login` does not say why it failed. A
successful one still proves the identifier exists.

`POST /login` answers one identical `401 { "error": "Not Allowed" }` for every rejection:

- an identifier that matches no account,
- an account that exists but is not verified,
- an account with no permitted continuation method under the current login policy,
- a failure to mint the pre-auth token.

Previously these produced three distinguishable bodies, so an unauthenticated caller could tell
which case it had hit. The reason is still recorded in the `login_failed` auth event metadata, so
operators keep the detail; it is simply no longer disclosed to the caller.

### What is still observable

A valid, verified identifier gets `200` with an ephemeral token, so `/login` still distinguishes
"this account exists and can sign in" from everything else. Some of this is inherent to
passwordless login: the client legitimately needs to know which continuation methods are available
before it can render anything.

Closing it fully means returning `200` with a decoy ephemeral token for unknown identifiers, and
making all 15 ephemeral-auth continuation endpoints behave identically for a decoy, including
making OTP and magic-link sends appear to succeed. Otherwise the oracle just moves one step later.
That is tracked in [issue #120](https://github.com/fells-code/seamless-auth-api/issues/120); it is
a redesign of the pre-auth surface, not a patch.

Two other signals are accepted on purpose:

- **Account lockout** answers `423` with `retryAfterSeconds`. Only a real account can be locked,
  so this discloses existence, but it requires prior failed attempts against that specific
  account, and suppressing it would leave a locked-out user with no way to understand what
  happened.
- **A malformed identifier** answers `400`. This does not depend on whether any account exists, so
  it is not an enumeration signal.

### Mitigating controls

Enumeration at scale is bounded by the rate limiters in
[`src/middleware/rateLimit.ts`](../src/middleware/rateLimit.ts) and by the lockout policy
(`LOCKOUT_POLICY`). Every attempt is recorded as an auth event, so bulk probing is visible in
`/internal/auth-events` and the `suspicious` metrics category.

### Note on 401 vs 403

Automated scans tend to flag `/login` for answering `401` on one path and `403` on another. Those
were the database-error branches, where the identifier lookup itself threw, not the not-found path.
Both now answer `500 { "error": "Server error" }`, so a database outage is reported as an outage
rather than as a failed login, and the two identifier branches agree.

## Ephemeral (pre-auth) token replay

**Posture: accepted, with mitigating controls named.**

Ephemeral tokens ([`src/lib/token.ts`](../src/lib/token.ts)) are validated by signature and expiry
but are not single-use, so a leaked one can be replayed until it expires.

The window is 5 minutes. Every continuation endpoint that accepts an ephemeral token is behind the
OTP, magic-link, or registration rate limiters, which are keyed per IP and per identity, so replay
cannot be used to generate OTPs in bulk. An ephemeral token also cannot be exchanged for anything
on its own: it authorizes a continuation step that still requires the OTP code, the magic-link
token, or a WebAuthn assertion.

That last clause depends on the continuation credential being single use, so it is worth saying
what backs it. A WebAuthn assertion is: the challenge it answers lives in `webauthn_challenges`
with a server-enforced TTL and a per-flow purpose, and
[`consumeChallenge`](../src/services/webauthnChallengeService.ts) spends it on read, before
verification, so no outcome leaves a challenge an assertion could be replayed against.

Making them single-use would mean tracking a `jti` in a short-lived store and consuming it on first
successful continuation. That adds server-side state to a deliberately stateless design and
introduces a failure mode where a dropped response leaves a user unable to retry a step they
legitimately started. Given the short TTL and the limiters, that trade was not judged worthwhile.

Revisit this if the ephemeral TTL is ever lengthened, or if a continuation endpoint is added that
has a side effect worth replaying on its own.

## Email and phone at rest

**Posture: plaintext, by design, and documented as such.**

`users.email` and `users.phone` are stored as plaintext columns
([`src/models/users.ts`](../src/models/users.ts)). They are lookup keys: `/login`, registration,
and admin search all query by them directly.

Encrypting them at rest would require deterministic encryption or a blind-index column so those
lookups still work, plus a backfill migration and a key-rotation story. That is a scoped project
rather than a configuration flag, and it is not currently planned.

Operators who need these fields encrypted at rest should use database-level encryption
(for example RDS/Aurora storage encryption, or full-disk encryption), which protects the same data
without breaking lookups.

## Synced passkeys

**Posture: blocked by default, deployment may allow.**

A multi-device credential is synced by a platform password manager, so its
private key exists somewhere outside the authenticator that created it. Every
iCloud Keychain and Google Password Manager passkey is one. That is what a
consumer wants and what an organisation issuing its own authenticators does not.

`authenticator_policy.syncedPasskeys` defaults to `block`, and registration
answers `403 { "error": "synced_passkey_not_allowed" }`. A deployment that wants
platform passkeys sets it to `allow`.

### Judged on eligibility, not current state

The decision is made on WebAuthn's backup **eligibility** flag, surfaced as
`credentialDeviceType: 'multiDevice'`, rather than on whether the credential is
currently backed up. A credential that _can_ leave the device is the exposure
whether or not it already has, and judging on current state would let one
register while unsynced and sync afterwards.

### Restricting authenticator models

`aaguidAllowList` and `aaguidDenyList` restrict which authenticator models may
register, by AAGUID. The deny list is applied first, so a model can be excluded
even when a broad allow list would otherwise admit it.

Both need `attestation: 'direct'` to mean anything. An authenticator that was
never asked to identify itself reports an all-zero AAGUID, so an allow list would
refuse everything. That combination is refused deliberately rather than waved
through, since admitting an unidentified authenticator would make the list
advisory, and the server logs the misconfiguration at startup.

### Requiring a known authenticator refuses self attestation

**Posture: if it cannot be looked up, it is not known.**

`requireKnownAuthenticator` refuses a credential whose attestation the FIDO
Metadata Service cannot be consulted about, which means self attestation and no
attestation, not only a model the service does not list.

The reason is a detail of how attestation works. Metadata is consulted per
attestation format, and only for a statement carrying a certificate chain. Every
format requires one except `packed`, which is also defined without: a statement
the credential signs with its own key. Nothing stands behind such a statement, and
nothing can be looked up for it, so a credential presenting one was previously
admitted without the setting ever being consulted. That made
`requireKnownAuthenticator` do nothing for precisely the authenticators it exists
to keep out.

The cost is real and worth stating: an authenticator that ships no attestation
certificate cannot enrol on a deployment that requires known authenticators. That
is what the setting means. A deployment that wants those authenticators leaves it
`false`, which is the default.

It applies only under `attestation: 'direct'`. Under `none` no credential presents
a chain, so the rule would refuse every registration rather than restrict
anything; the server logs that misconfiguration at startup instead.

One limit, carried over rather than introduced. When the metadata blob cannot be
fetched at startup the server continues without metadata validation, because
refusing every registration on a transient network failure is worse than the risk
it guards against. In that degraded state a certificate chain is checked for
structure and signature but is not traced to any trust anchor, so a self-signed
attestation certificate satisfies this rule where a self attested statement would
not. `credentials.attestationVerified` is false either way, so the audit trail
still shows that nothing was checked. Changing the degraded posture to fail closed
is a separate decision from this one.

### What `attestationVerified` records

`credentials.attestationVerified` is true only when the FIDO Metadata Service held
a statement for the credential's AAGUID. It used to be derived from the attestation
format and whether the service had come up, which claimed a check for credentials
that were never looked up at all.

`credentials.attestationType` sits beside the format and records `none`, `self` or
`basic`. The format alone cannot separate the last two: a manufacturer-signed
statement and one a credential signed for itself are both `packed`.

## Token audience

**Posture: `aud` is the deployment's own issuer URL.**

Access, refresh, and ephemeral tokens are all signed with `aud` equal to `ISSUER`
([`src/lib/token.ts`](../src/lib/token.ts)). Verifiers enforce it: the Seamless adapter checks
`aud === audience`, and the deployment contract requires the adopter's `audience` to equal its
`authServerUrl`, which is byte-identical to `ISSUER`.

A per-deployment audience is deliberate. A single global literal such as `seamless-auth` would make
every tenant share one audience string, so a token minted by one instance would satisfy an audience
check on another.

The internal service-token path
([`src/middleware/authenticateServiceToken.ts`](../src/middleware/authenticateServiceToken.ts))
does use `aud: seamless-auth` with `iss: seamless-portal-api`. That is a different token family:
machine-to-machine credentials minted by the portal API, not user tokens minted here. The two
schemes are intentionally separate, and neither verifier accepts the other's tokens.

## Requests from an origin that is not allowlisted

**Posture: refused by the server, not left to the browser.**

A cross-origin request whose `Origin` is not in `APP_ORIGINS` is answered `403 { "message": "CORS
policy does not allow this origin." }` and the route never runs
([`src/app.ts`](../src/app.ts)).

The alternative, and what this server used to do, is to omit the
`Access-Control-Allow-Origin` header and carry on. The browser then discards the response, so the
caller learns nothing, but the request has already been executed. For an authentication server that
is the wrong way round: a disallowed origin should not be able to make the server act, only to be
denied a reading of what it did.

Two kinds of request are deliberately not refused:

- **No `Origin` header at all.** Server adapters, backends and command-line callers send none, and
  this API's contract is bearer credentials from a trusted server adapter. CORS has nothing to say
  about a caller that is not a browser.
- **Same-origin.** A browser sends `Origin` on every state-changing request, including same-origin
  ones, so without this the admin console at `/console` would need its own host in `APP_ORIGINS`
  despite being served by this very process. The comparison is on host, not scheme, so that it does
  not silently depend on `TRUST_PROXY` being set behind a TLS-terminating proxy.

The refusal carries no `Access-Control-Allow-Origin` header. Naming an allowed origin to a caller
that is not one discloses part of the allowlist and helps the browser not at all.

The refusal is recorded as one `request_suspicious` auth event with the real client address and user
agent, and the rejected origin in an `origin` metadata field. It used to be recorded with the origin
string in the `ipAddress` field, which made the trail hard to read.

## Concurrent sessions per user

**Posture: uncapped by default, and a cap evicts rather than refuses.**

`max_concurrent_sessions` bounds how many sessions one user may hold at once. It
defaults to no limit, so an instance that predates the setting is unaffected.
Unlimited is `null` rather than `0`, and the schema refuses `0`, because zero
would otherwise read as "no sessions allowed" and lock every user out of a
deployment that meant to remove the cap.

When a signed-in user is at the limit, the new sign-in **succeeds** and their
oldest session is revoked with `revokedReason: 'concurrent_session_limit'`, and a
`session_evicted` auth event names the session that ended. Refusing the new
session instead would lock a user out of the device in front of them until
something they may not have access to expires, which for the shared workstations
this setting exists to protect is the common case rather than the edge one.

Lowering the limit leaves users above it. Each converges on their next sign-in,
which evicts everything above the cap in one pass rather than shedding one
session per login indefinitely.

Enforcement runs before the new session row is created, so the limit counts the
session about to exist: at a limit of 3, a user holding 3 ends up with 3, not 4.
It never throws. A session that cannot be revoked is logged and the sign-in
continues, because failing an authentication over a housekeeping step is worse
than briefly exceeding the cap.

This is NIST 800-53 AC-10.

## Audit write failure

**Posture: the trail may be lost, no security control may be.**

`AuthEventService` still swallows a failed write to `auth_events`. 137 call sites
await it, many from inside error handlers, so throwing there would turn a
bookkeeping failure into a failed request and would take down the very paths that
report problems.

What changed is that a failure is no longer silent, and no longer takes anything
with it.

### Nothing security-relevant is derived from the audit trail

Account lockout used to count failed attempts by querying `auth_events`. The
control and its telemetry were one data path, and that path fails open: a
condition that degraded audit writes while leaving the service running stopped
failures being counted, so lockout silently stopped enforcing on every account
while authentication carried on. Disk exhaustion, a table lock, a failed
migration or pool exhaustion would all do it, and the missing records are the same
missing records that would have shown it happening.

Failed attempts are now recorded in `auth_failures`, written separately from the
audit event and read only by the lockout policy. Losing the trail no longer loses
the control.

### An unknown count means locked

`getUserLockoutStatus` refuses rather than guessing when it cannot read the
counter. An authentication the server cannot vouch for is refused with the same
`423` a locked account gets, rather than admitted because the count came back
empty.

### Failures are reported where monitoring already looks

`GET /health/status` answers `200 { "message": "System up, audit degraded",
"degraded": { "audit": { … } } }` for five minutes after a failed audit write. The
healthy body is unchanged, so anything already parsing it is unaffected, and the
status stays `200` because the service is still serving and should not be pulled
from a load balancer for this. This is the defined action NIST 800-53 AU-5 asks
for on audit logging failure; a line in the application log is not one, because
nothing reads it.

### What is still accepted

An audit write that fails is still a lost record. Recording is best effort by
design, and the tradeoff is stated here rather than made by default. A deployment
that needs authentication to fail closed on audit failure does not have that
option today.

`auth_failures` rows are not pruned, which matches `auth_events`. Retention is
[issue #173](https://github.com/fells-code/seamless-auth-api/issues/173).
