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
