# Security Posture

Decisions that are deliberate tradeoffs rather than open bugs. Each one states what the server
does, why, and what would change it. If you are looking for how to configure the server, see
[configuration.md](./configuration.md); for operational hardening, see
[production-operations.md](./production-operations.md).

## User enumeration on `/login`

**Posture: closed.** `POST /login` answers the same way for an identifier that has an
account and one that does not, and every endpoint that accepts the resulting pre-auth
token answers the same way for both.

An identifier with no usable account gets `200` with a **decoy** pre-auth token: a real,
signed ephemeral token over a subject that belongs to nobody. The four cases that used to
answer `401` all take this path:

- an identifier that matches no account,
- an account that exists but is not verified,
- an account with no permitted continuation method under the current login policy,
- an account whose identifier differs only in case or phone formatting.

The reason is still recorded in the `login_failed` auth event metadata, now with
`decoy: true`, so operators keep the detail that the caller no longer gets.

### Why the decoy has to survive the next request

Returning `200` for an unknown identifier is worth nothing on its own. If the next
request distinguished the decoy, the oracle would simply have moved one step later. All
fifteen endpoints that accept an ephemeral token therefore answer for a decoy the way
they answer for a real account:

| Endpoint group           | A decoy gets                                                    |
| ------------------------ | --------------------------------------------------------------- |
| OTP send (4)             | `200 { message: 'success', token }`, with nothing sent          |
| OTP verify (4)           | `401 { error: 'Not allowed' }`, the body a wrong code gets      |
| Magic link request       | `200`, the same "if an account exists" body a real request gets |
| Magic link poll          | `204`, the state a real account sits in until someone clicks    |
| WebAuthn register start  | A registration challenge, with no challenge record stored       |
| WebAuthn register finish | `403 { error: 'Missing challenge' }`                            |
| WebAuthn login start     | An assertion challenge over a fabricated credential id          |
| WebAuthn login finish    | `401 { error: 'Authentication failed.' }`                       |
| TOTP login verify        | `401 { error: 'totp_verification_failed' }`                     |

Policy-dependent branches are reproduced rather than skipped. A deployment with
`email_otp` disabled answers `403 login_method_disabled` for every identifier, so a decoy
that returned success there would be the one that stood out.

The WebAuthn login case is worth calling out. A real account with no passkey answers
`401`, so a decoy with an empty allow-list would have been sorted into that bucket and
separated from every account that has one. It offers one fabricated credential instead.

### How a decoy is built

Everything derives from one HMAC over the normalised identifier, keyed with
`DECOY_SUBJECT_SECRET` (falling back to `API_SERVICE_TOKEN`). That gives three
properties:

- **Stable.** The same unknown identifier yields the same subject every time. A real
  identifier resolves to the same row every time, so a decoy that rerolled its subject
  would be an oracle by itself.
- **Unguessable.** The subject is a well-formed v4 UUID and cannot be told apart from a
  real user id, or minted, without the key.
- **Stateless.** Nothing is written. A decoy is issued for any identifier a stranger can
  type, so if probing one wrote a row, closing this would have opened a way to fill the
  disk.

A decoy is recognised on the way back in by its subject not resolving to a user row.
There is deliberately no `decoy` claim: anyone can base64-decode a JWT, and a claim
saying which tokens are fake is the whole point given away.

The stand-in principal carries a synthetic email because the OTP and magic link rate
limiters key on `req.user.email`. Left empty they fall back to an IP bucket, so every
unknown identifier probed from one address would have shared a counter while every real
one got its own, which is a working oracle built out of `429`s.

### Why a decoy does not always claim everything

`loginMethods` is filtered by what an account can actually do: one with no passkey is not
offered `passkey`, and one with no phone is not offered `phone_otp`. A decoy that always
claimed the full permitted set would therefore make any narrower set proof that a real
account exists, which is the original oracle with extra steps.

So a decoy's shape is derived from its subject alongside everything else: about half have
a passkey and about half have a phone, stable per identifier. A narrow method list is
then as likely to be a decoy as a real account, and one probe settles nothing.

The shape has to be honoured downstream as well. A real account with no phone answers
`400` on `/otp/generate-phone-otp`, so a decoy shaped without one answers `400` there too.
Otherwise the shape that was hiding it becomes the thing that shows it.

### Every rejection a real account can reach, a decoy reaches too

A decoy responder that only reproduces the success path is not finished. Any `400` a real
account can be made to answer is an oracle if a decoy answers `200` to the same request,
and the ones that matter are the ones a caller can trigger on purpose:

- `/magic-link?redirectUri=` pointing somewhere the configured origins do not allow
  answers `400 Redirect URI is not allowed`. A caller picks that value, so this is one
  deliberately bad request away. The decoy responder runs the same `resolveMagicLinkUrl`
  validation.
- `/magic-link` with no identifiable device metadata answers `400 Invalid device data`,
  and omitting a `User-Agent` header is enough to get there. The decoy responder runs the
  same fingerprint check.

- `/webauthn/login/start` filters the account's credentials by the requested
  `credentialId` and `prf` and answers `401 Credentials not found` when nothing survives.
  A caller can ask for a credential id no credential can have, which **every** real
  account refuses, so a decoy that returned a challenge anyway was identifiable in two
  requests regardless of account state or policy. The decoy's single fabricated credential
  is filtered the same way, and a decoy shaped without a passkey refuses outright. The
  refusal is `res.send`, not `res.json`; a JSON body would differ in content type.
- `/webauthn/register/start` answers `400 attachment_not_allowed` when the requested
  attachment contradicts a pinned policy, and passes the account's enrolled credentials as
  `excludeCredentials`. A decoy offers its fabricated credential there when its shape has
  one, since an always-empty list says "this subject has no passkey" to anyone who looks,
  and reproduces the attachment branch.

Neither validation writes anything, so reproducing them costs a decoy nothing.

### What this still does not cover

`/webauthn/register/start` echoes the account's email as `user.name` in the options it
returns, because that is what an authenticator displays. A decoy has no real address, so
it echoes its synthetic one, and a caller that reads `user.name` sees an `@example.invalid`
address where a real account shows the identifier the caller typed. That is a complete
oracle, one request past `/login`.

Closing it means the decoy echoing the identifier that was supplied, which it cannot do:
a decoy is rebuilt from its subject alone, and the subject is a one-way HMAC. Carrying the
identifier would mean putting it in the ephemeral token, and putting it only in decoy
tokens would be the `decoy` claim by another name, so every ephemeral token would have to
carry it. That is a second change to the token contract and a second coordinated release,
so it is tracked separately rather than folded in here.

For the same reason, a decoy's shape is derived from its subject and cannot depend on
which kind of identifier was looked up. `/login` finds a phone account by its number, so
such an account always has a phone and is always offered `phone_otp`, while only about
half of decoys are. Where `phone_otp` is an enabled method, a phone identifier whose
answer omits it is therefore a real account.

One exception is forced. A real account with no permitted method is itself answered as a
decoy, so an empty list is something only a decoy could produce, and under a passkey-only
policy that would be every decoy the derived shape gave no passkey to. A decoy whose
derived shape leaves it with no methods falls back to the full permitted set, which is
what a usable account under that policy answers.

### Timing

Identical bodies that arrive at measurably different times still answer the question. The
real path reads the users table, the lockout counter, the credentials table and the login
policy; the decoy path reads only the policy.

`LOGIN_RESPONSE_FLOOR_MS` (default `250`) holds every `/login` answer to a minimum, which
removes the difference as long as both paths finish under it. Set it above the slowest
real login the deployment sees. It is an environment variable rather than a
`system_config` key because that schema is shared through `@seamless-auth/types`, and a
key there means a coordinated release across both SDKs for an operational tuning knob.

### What is still observable

- **Account lockout** answers `423` with `retryAfterSeconds`. Only a real account can be
  locked, so this still discloses existence. It requires prior failed attempts against
  that specific account, and suppressing it would leave a locked-out user with no way to
  understand what happened. Accepted, unchanged.
- **A malformed identifier** answers `400`. This does not depend on whether any account
  exists, so it is not an enumeration signal.
- **External delivery mode** returns a fabricated code and the decoy's synthetic address
  rather than the identifier the caller supplied, so a caller comparing the two can tell.
  That mode requires a valid internal service token, which makes the caller a trusted
  backend that can enumerate through the admin API anyway. Accepted, and the reason it is
  acceptable is the service token, not the fabrication.
- **A deleted or revoked account** mid-flow is answered as a decoy rather than with a
  distinguishable `401`. That is the intended behaviour, and it means such a user sees a
  continuation that quietly never succeeds rather than a clear rejection.

### Note on 401 vs 403

Automated scans tend to flag `/login` for answering `401` on one path and `403` on
another. The database-error branches, where the identifier lookup itself threw, both now
answer `500 { "error": "Server error" }`, so an outage is reported as an outage rather
than as a failed login. `/login` no longer returns `401` at all.

### Keeping it closed

`defineRoute` refuses to register a route that accepts an ephemeral token and declares no
decoy responder. A new pre-auth endpoint that forgot one would hand the oracle straight
back, and that failure is silent at runtime and invisible in a diff, so it is a
registration-time error rather than a convention.

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
