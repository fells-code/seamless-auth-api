# seamless-auth-api

## 0.8.0

### Minor Changes

- 0e6664d: Give WebAuthn challenges their own store, with an expiry and one-time use.

  Challenges lived in a single `users.challenge` column shared by registration,
  login and step-up. Three consequences, all fixed here:

  - **Flows clobbered each other.** Starting a login invalidated a registration
    already in flight for the same user, and a second tab invalidated the first.
    Challenges are now keyed by user and flow, so registration, login and step-up
    can be outstanding at once.
  - **Nothing expired.** The column had no lifetime, so a challenge stayed valid
    until some later flow happened to overwrite it. The `timeout` in the credential
    options is only a hint to the browser and was never enforced. Challenges now
    expire server side after five minutes, comfortably longer than that hint so no
    legitimate ceremony is cut short.
  - **A challenge could outlive its ceremony.** It is now spent when verification
    reads it, before anything else can fail, so an attempt that fails leaves
    nothing redeemable behind.

  A magic link completing also spends any half-finished WebAuthn ceremony for that
  user, preserving what the old defensive clear did.

  `users.challenge` and `users.challengeContext` are no longer read or written.
  They are left in place so this release can be rolled back, and should be dropped
  in a follow-up once it has run in production.

- 8b74a80: Support attestation, and validate it against the FIDO Metadata Service.

  Registration hardcoded `attestationType: 'none'`, so authenticators never
  identified themselves and there was nothing for the FIDO Metadata Service to
  validate. FIDO Server Requirements v2.3 requires a server to validate
  attestation certificate chains and to support validation through that service.

  `authenticator_policy.attestation` now chooses. `none` stays the default, which
  suits a consumer deployment: attestation identifies a user's hardware and most
  relying parties have no use for it. `direct` requests a statement, and the
  metadata service is prepared at startup so the attestation verifiers validate
  against it.

  `authenticator_policy.requireKnownAuthenticator` decides what happens to an
  authenticator the metadata service does not list. False, the default, registers
  it anyway; true refuses it.

  Credentials now record `attestationFormat` and `attestationVerified`, so an audit
  can tell an unattested credential from one whose attestation was actually
  checked. Neither is recoverable after the fact, so existing credentials report
  neither.

  The metadata service never blocks startup. A blob that cannot be fetched is a
  degraded state, not a reason an authentication server should refuse to start, so
  it is logged and registration continues without metadata validation.
  `requireKnownAuthenticator` is deliberately not honoured in that state, because
  refusing every registration on a transient network failure is worse than the risk
  it guards against.

  Changing `attestation` needs a restart, because the metadata service is prepared
  once at boot.

  Requires `@seamless-auth/types` 0.14.0.

- 365bc95: Read the JWKS public keys document under one name, and document rotation properly.

  **Fixes a deployment trap.** `validateEnvs.sh` required `JWKS_PUBLIC_KEYS`, and the
  configuration reference and `.env.example` named only that, but token verification read
  `SEAMLESS_JWKS_PUBLIC_KEYS`. A deployment that set exactly what this API asked for
  started cleanly and then threw on every JWT verification, because
  `getPublicKeyByKid` could not find the secret. The failure arrives at the first
  authenticated request rather than at boot, which is the worst place for it.

  Everything now uses `SEAMLESS_JWKS_PUBLIC_KEYS`: the entrypoint check, the
  `/.well-known/jwks.json` handler, the configuration reference, and `.env.example`.

  **Breaking for anyone setting only the unprefixed name**, who is already broken and
  does not know it. After this they fail to start, with the variable named, instead of
  serving a deployment that cannot verify a token it just issued.

  **Rotation is documented rather than implemented.** The acceptance criteria in the
  rotation issue are met by the read path that already exists: the document is a list,
  every key in it is published and can verify, and only the active kid signs. What was
  missing was a written procedure, which `docs/production-operations.md` now carries as
  the three-step overlap (add, flip, retire), including why the steps cannot be
  collapsed and why key ids must be environment-variable safe.

  The server deliberately does not rotate its own keys. It has no secret-store write
  path, and environment variables are fixed for a process's lifetime, so a server that
  rotated could not observe the result without a restart it cannot trigger. The document
  belongs to whatever manages the secrets.

  Accordingly the empty `ensureKeys()` production branch is removed, along with
  `initKeys`, their specs and the dev-stack invocation. It advertised a runtime rotation
  capability that is not going to exist, and its development branch wrote a keypair to
  `./keys` that nothing has ever read: `signingKeyStore` keeps dev keys under
  `./keys/dev` and generates them lazily.

- 642b823: Allow hardware security keys to be enrolled.

  `GET /webauthn/register/start` pinned `authenticatorAttachment` to `platform`, which
  hid roaming authenticators from the browser picker entirely, so USB and NFC security
  keys could not be registered at all. Only built-in authenticators (Touch ID, Windows
  Hello, Android biometrics) were reachable.

  Registration now leaves the attachment unset by default, so the browser offers both
  kinds. Callers that want to narrow the picker can pass `?attachment=platform` or
  `?attachment=cross-platform` on `register/start`; anything else is rejected with a 400.

  This changes the default enrolment experience: users who previously saw only the
  built-in authenticator will now also be offered a security key. Deployments that
  genuinely want the old behaviour should pass `?attachment=platform`.

- fdf9613: Correlate audit events to the session they happened in.

  Audit events gain `session_id`, and `GET /admin/auth-events` accepts a
  `sessionId` filter, so a suspicious session can be turned into its event history
  and an event traced back to the session it came from.

  The session is read from the request rather than passed at each of the 135 log
  call sites. The bearer middleware already sets it for any access-token call, so
  authenticated events correlate without any of those sites changing, and anything
  before a session exists stays null. A caller can still name a session
  explicitly, which is what an administrator acting on someone else's session
  needs.

  The column is nullable and not backfilled. The session for historical events is
  unrecoverable.

  Requires `@seamless-auth/types` 0.11.0.

- 30c3971: Record who performed an administrative action.

  Audit events gain `actor_user_id`. An administrator acting on someone else's
  account is now recorded with the target in `user_id` and the administrator in
  `actor_user_id`, so the trail no longer reads as though the user did it to
  themselves. `GET /admin/auth-events` accepts an `actorUserId` filter, which
  answers "what did this administrator do" rather than only "what happened to this
  user".

  Two administrative actions that previously wrote no audit event at all now write
  one:

  - Deleting a user through the admin API
  - Revoking every session for a user

  The user deletion is now awaited before the response, so a failure surfaces as a
  500 rather than a success with the account still present, and the audit event
  records a deletion that actually happened.

  The column is nullable and not backfilled. The actor for historical events is
  genuinely unknown, and inventing one would be worse than leaving it empty.

  Requires `@seamless-auth/types` 0.10.0.

- c60c3e3: Answer a schema validation failure with the documented error body instead of a raw
  `ZodError`.

  **Behaviour change to the error contract.** A request that fails its route's `params`,
  `query` or `body` schema was refused with `res.status(400).json(error)`, passing the
  `ZodError` straight to the serializer. That produced
  `{ "name": "ZodError", "message": "<the issues, JSON encoded into a string>" }`, which
  has no `error` key at all. Every route declares `400: ErrorSchema`, where `error` is
  required, so the response violated the contract the route published for itself, and a
  client had nothing stable to branch on.

  Nothing caught it. The response schema check is installed by the handler wrapper, and
  validation fails before that wrapper runs, so the mismatch was never even logged.

  For a consumer the practical effect was worse than a missing code. The React SDK reads
  `error` and falls back to `message`, so with no `error` present, `registerPasskey()`
  surfaced the entire encoded issue list as `error.message`, ready to be rendered to a
  user by an app doing the documented thing with an unrecognised failure.

  Validation failures now answer with:

  ```json
  {
    "error": "invalid_request",
    "message": "Request failed schema validation.",
    "details": { "issues": [{ "path": ["attachment"], "code": "invalid_value", "message": "..." }] }
  }
  ```

  `error` carries the stable code. `details` names the rejected fields, following the same
  reasoning as `AdminValidationErrorSchema`, which exists because a plain error schema
  would strip that list before it reached the caller. Issues are mapped field by field
  rather than passed through, so a refusal does not echo the submitted value back.

  `defineRoute` now declares `ValidationErrorSchema` as the `400` for any route that
  validates a request, so `openapi.json` documents the response that validation actually
  returns. A route that already declares a richer `400` keeps it. `error` stays required
  everywhere, so a consumer reading only that field is unaffected, and `details` is
  additive.

  A throw that is not a `ZodError` is passed to the error handler rather than being
  reported as a bad request, since it means a server fault rather than a malformed
  request.

- 40e17ca: Refuse synced passkeys by default, and let a deployment restrict authenticator models.

  **Breaking. Read this before upgrading.**

  `authenticator_policy.syncedPasskeys` defaults to `block`. A multi-device
  credential is synced by a platform password manager, so its private key exists
  somewhere outside the authenticator that created it. **Every iCloud Keychain and
  Google Password Manager passkey is one.** On upgrade, a deployment relying on
  platform passkeys stops enrolling them and registration answers
  `403 { "error": "synced_passkey_not_allowed" }`.

  To keep the previous behaviour:

  ```json
  AUTHENTICATOR_POLICY={"syncedPasskeys":"allow", ...}
  ```

  This closes the gap between what the product did and the design position it was
  documented as holding, which was blocked by default with the agency able to
  enable. Existing credentials are unaffected; this governs new registrations.

  The decision is made on backup **eligibility** rather than current backup state.
  A credential that can leave the device is the exposure whether or not it already
  has, and judging on current state would let one register while unsynced and sync
  afterwards.

  Also adds `aaguidAllowList` and `aaguidDenyList`, which restrict which
  authenticator models may register. The deny list is applied first, so a model can
  be excluded even when a broad allow list would admit it. Both need
  `attestation: 'direct'` to mean anything, since an authenticator that was never
  asked to identify itself reports no usable AAGUID; an allow list set without it
  refuses everything, and the server says so at startup rather than leaving it to
  be discovered one failed enrolment at a time.

  Refusals are distinguishable, `synced_passkey_not_allowed` and
  `authenticator_not_allowed`, and each is recorded as a failed registration with
  the reason.

- 1f5d98c: Require identity proofing on admin-assisted device replacement.

  **Breaking.** `POST /admin/users/:userId/recovery/device-replacement` now
  requires a `proofing` object and answers 400 without one:

  ```json
  {
    "proofing": {
      "method": "in_person",
      "evidenceRef": "TICKET-1042"
    }
  }
  ```

  `method` is `in_person` or `remote_exception`. A remote exception is refused
  unless it names an `approver`, so taking the weaker path is deliberate and
  attributable. `evidenceRef` is a pointer such as a ticket number, not the
  evidence itself, because it is written to the audit trail where identifiers are
  redacted.

  This endpoint revokes every session, removes every passkey and disables TOTP. It
  previously recorded nothing about how the operator established who they were
  talking to, which made a recovery impossible to review afterwards.

  The audit event now carries the proofing record and the acting administrator.
  The acting admin currently rides in event metadata; it moves to a first-class
  column when `auth_events` gains one.

  Callers sending an empty body and relying on the clearing defaults must now send
  proofing. Those defaults are unchanged. Requires `@seamless-auth/types` 0.9.0.

- 09d3df3: Ask for exactly the user verification that will be enforced.

  Registration advertised `userVerification: 'preferred'`, telling the
  authenticator verification was optional, and then rejected a response that
  skipped it, because SimpleWebAuthn's `requireUserVerification` defaults to true
  and this server never set it. A user on an authenticator that skips verification
  completed the whole ceremony and failed at the last step, having never been asked
  to verify. Authentication separately asked for `required`, so the two halves
  disagreed.

  `authenticator_policy.userVerification` now drives both, for registration and
  authentication, so what the browser is asked for and what the server accepts come
  from one value and cannot drift. It accepts `required`, `preferred` or
  `discouraged` and defaults to `required`.

  The default does not change what is accepted, since that was already enforced. It
  changes what is asked for, so an authenticator is told to verify rather than
  being allowed to skip and be rejected afterwards.

  Step-up deliberately still requires verification regardless of the policy. It
  exists to re-verify the human, and without verification it is a second signature
  from a key the session already proved it holds.

  Requires `@seamless-auth/types` 0.13.0.

- d78bfc1: Refuse a request from an origin that is not allowlisted, instead of running it.

  The CORS origin callback rejected an unknown origin by returning `false` rather
  than an error, so the handler that exists to turn a rejection into a `403` keyed
  off an error message that was never raised and could not fire. What actually
  happened was that `cors` omitted the `Access-Control-Allow-Origin` header and
  called `next()`: the route ran, and only the browser discarded the response. For
  an authentication server that is the wrong way round, since a disallowed origin
  should not be able to make the server act.

  An unlisted origin is now refused with `403 { "message": "CORS policy does not
allow this origin." }` before the route runs, preflights included.

  Two kinds of request are deliberately still allowed. One carrying no `Origin`
  header at all, which is every server adapter, backend and command-line caller.
  And a same-origin request: a browser sends `Origin` on every state-changing
  request, same-origin ones included, so without this the admin console at
  `/console` would need its own host in `APP_ORIGINS` despite being served by this
  very process. That comparison is on host rather than scheme, so it does not
  silently depend on `TRUST_PROXY` being set behind a TLS-terminating proxy.

  The refusal no longer sets an `Access-Control-Allow-Origin` header naming the
  first allowed origin, which disclosed part of the allowlist to a caller that was
  not on it and helped the browser not at all. It is recorded as one
  `request_suspicious` event carrying the real client address and user agent, with
  the rejected origin in an `origin` metadata field rather than in `ipAddress`.

- e58ef6c: Stop recording a WebAuthn registration success before anything is registered.

  `GET /webauthn/register/start` logged `webauthn_registration_success` at the end
  of options generation, before the client had done anything and before any
  credential existed. Every abandoned or failed registration produced a success
  event, so registration counts, dashboards and anomaly detection were all
  measuring the wrong thing. Because outcome is derived from the `_success`
  suffix, those events were also counted as successful WebAuthn activity in the
  metrics.

  Issuing options now logs `webauthn_registration_challenge`, matching
  `login_challenge` on the login path. It categorises as `webauthn` with outcome
  `other`, so it no longer inflates the success figures. The real
  `registration_success` stays where it belongs, on verified registration in
  `/webauthn/register/finish`.

  `webauthn_registration_success` is removed from the declared event types, since
  it is now emitted nowhere and this repository deliberately prunes types nobody
  writes so consumers do not filter and alert on names that never arrive. Stored
  events keep that type and remain readable and filterable by exact type; they are
  no longer swept into the `webauthn` category filter.

- 15005f2: Make session lifetimes configurable, and give the idle bound a chance to fire.

  Session expiry came from two hardcoded constants, both one day. Because they
  were equal, `idleExpiresAt` and `expiresAt` always landed on the same instant,
  so the idle bound could never fire before absolute expiry. In practice there was
  no idle timeout at all, despite the session model carrying the column and the
  lookup queries filtering on it.

  Two changes:

  - The absolute session lifetime now comes from `refresh_token_ttl`, which
    already existed and was already reported to clients as `refreshTtl`. It was
    not previously applied to the session row, so an instance with
    `REFRESH_TOKEN_TTL=30d` told clients thirty days and expired the session after
    one. Setting it now does what it says.
  - The idle bound comes from the new `session_idle_ttl`
    (`SESSION_IDLE_TTL`), default `8h`.

  **Behaviour change.** On stock configuration a session that goes unrefreshed
  now ends after 8 hours rather than 24. Any client refreshing normally is
  unaffected, because rotation resets the bound and access tokens are far shorter
  lived; only genuinely idle sessions end sooner. Instances that want the previous
  behaviour can set `SESSION_IDLE_TTL=1d`, and deployments with a stricter posture
  typically want 15m to 30m.

  An instance that previously relied on `REFRESH_TOKEN_TTL` being longer than one
  day will see sessions live as long as that value now actually says, which is
  longer than before. Check that value if it was set to something large on the
  assumption it was inert.

  Requires `@seamless-auth/types` 0.8.0.

- 6ff06c4: Add the FIDO2 conformance test interface behind an environment flag.

  The FIDO2 conformance test tools drive a server through a fixed message interface
  rather than through its own API, so with no such surface conformance
  self-validation could not be run at all. That is the first gate of FIDO Functional
  Certification, and the only part of it reachable without an assessor, a customer or
  a sponsoring agency.

  Four paths now serve that interface under `/conformance`, and only when
  `FIDO_CONFORMANCE_MODE=true`. The flag is refused under `NODE_ENV=production`,
  matching `DISABLE_AUTH_RATE_LIMITS` and `ALLOW_UNCREDENTIALED_DELIVERY_SECRETS`.
  With the flag unset nothing is registered: the routes never reach Express, never
  reach the OpenAPI document, and the paths answer the ordinary 404. Enforcement is
  in the tests, not in the documentation, because the surface takes no
  authentication, issues no sessions, honours whatever attestation conveyance the
  caller asks for instead of the deployment policy, and is expected to accept
  malformed input.

  What a run validates is the shipping WebAuthn verification: the same library calls
  the real controller makes, the same advertised algorithm list, and the same RP ID
  and origins from `system_config`. Storage is not shared. Conformance users and
  credentials are held in memory, because the tools invent hundreds of accounts and
  replay ceremonies on purpose.

  Three optional variables point metadata verification at the tools rather than the
  production FIDO Metadata Service, which signs its blobs with a different root:
  `FIDO_CONFORMANCE_MDS_URLS`, `FIDO_CONFORMANCE_MDS_ROOT_CERT_FILE` and
  `FIDO_CONFORMANCE_METADATA_DIR`. Conformance mode also brings the metadata service
  up whatever this deployment has configured, since the surface honours the
  conveyance the tools ask for.

- 6658a49: Make `requireKnownAuthenticator` refuse a credential that cannot be looked up,
  and stop claiming attestation was verified when it was not.

  **Behaviour change.** A deployment running `attestation: 'direct'` with
  `requireKnownAuthenticator: true` now refuses a credential that self attests or
  presents no attestation. Authenticators that ship no attestation certificate can
  no longer enrol there. Both settings are off by default, so only a deployment
  that explicitly asked for known authenticators is affected, which is the
  population the change is for.

  The setting only ever set the metadata service to a strict verification mode, and
  that mode is consulted per attestation format, only for a statement carrying a
  certificate chain. Every format requires one except `packed`, which is also
  defined without: a statement the credential signs with its own key. Nothing
  stands behind such a statement and nothing can be looked up for it, so a
  credential presenting one was admitted without the setting ever being consulted.
  An agency that had asked for known authenticators only was getting no
  restriction at all against exactly the authenticators the setting exists to keep
  out. The refusal reuses the existing `authenticator_not_allowed` error, with the
  reason recorded in the audit event.

  The rule applies only under `direct`. Under `none` no credential presents a
  chain, so it would refuse every registration rather than restrict anything, and
  the server now logs that misconfiguration at startup the way it already does for
  an allow list set without attestation.

  `credentials.attestationVerified` is now true only when the metadata service
  actually held a statement for the credential's AAGUID. It was derived from the
  attestation format and whether the service had come up, so a self attested
  credential was recorded as verified against metadata it had never been compared
  to. That field exists so an audit can tell an unattested credential from a
  checked one, and it could not.

  A new nullable `credentials.attestationType` column records `none`, `self` or
  `basic`. The format alone cannot separate the last two, since a
  manufacturer-signed statement and one a credential signed for itself are both
  `packed`. Existing rows are left null; neither value can be recovered after the
  fact.

- c502782: Make `POST /login` non-enumerable with decoy pre-auth tokens.

  **Breaking behaviour change.** `POST /login` no longer returns `401`. An
  identifier with no usable account, which previously meant an unknown identifier,
  an unverified account, or an account with no permitted continuation method, now
  gets `200` with a decoy ephemeral token: real, signed, and indistinguishable
  from one issued to a genuine account.

  A client that branched on `401` to mean "no such user" will now follow the normal
  continuation flow instead, and the failure surfaces at the continuation step, as
  a wrong OTP or an assertion that cannot verify, rather than at login. That is the
  point of the change: there is no longer an answer to give. `@seamless-auth/react`
  and `seamless-cli` already fall back to a default method list rather than reading
  `401` as a terminal state, but any caller that special-cases it needs updating.

  Returning `200` for an unknown identifier is worth nothing unless the next
  request keeps the secret, so all fifteen endpoints that accept a pre-auth token
  now answer for a decoy the way they answer for a real account. OTP sends report
  success without sending. OTP and TOTP verifies fail the way a wrong code fails.
  The magic link request returns its usual "if an account exists" body and the poll
  returns `204` indefinitely. WebAuthn returns a plausible challenge, offering one
  fabricated credential at login start, because a real account with no passkey
  answers `401` there and an empty allow-list would have sorted the decoy into that
  bucket. Policy-dependent branches are reproduced, so a deployment with `email_otp`
  disabled still answers `403 login_method_disabled` for every identifier.

  A decoy derives from one HMAC over the normalised identifier, keyed with the new
  optional `DECOY_SUBJECT_SECRET` (falling back to `API_SERVICE_TOKEN`). The same
  unknown identifier always maps to the same subject, since one that rerolled would
  be an oracle by itself, and the subject is a well-formed v4 UUID that cannot be
  told from a real user id without the key. Nothing is written for a decoy: they are
  issued for any identifier a stranger can type, so persisting them would trade an
  enumeration oracle for a way to fill the disk. There is deliberately no `decoy`
  claim, since anyone can decode a JWT.

  A decoy's account shape is derived alongside its subject rather than fixed:
  about half "have" a passkey and about half a phone, stable per identifier.
  `loginMethods` is filtered by what an account can actually do, so a decoy that
  always claimed the full permitted set would have made any narrower set proof that
  a real account exists. A decoy left with no methods by its derived shape falls
  back to the full set, since a real account with none is itself answered as a
  decoy and an empty list would otherwise be the old `401` in a different costume.

  The new optional `LOGIN_RESPONSE_FLOOR_MS` (default `250`) holds every `/login`
  answer to a minimum. The real path reads more tables than the decoy path, and
  identical bodies arriving at measurably different times still answer the question.
  Set it above the slowest real login the deployment sees, or `0` to turn it off.

  `defineRoute` now refuses to register a route that accepts an ephemeral token and
  declares no decoy responder, so a new pre-auth endpoint cannot silently reopen
  the oracle.

- 1dca9f7: Upgrade to Express 5.

  The HTTP contract is unchanged: every behaviour Express 5 alters by default is
  pinned or restored, so no caller has to adapt. Four things needed real work.

  - **Query validation stopped applying.** Express 5 exposes `req.query` as a
    getter with no setter that re-reads the URL on every access, so the assignment
    in `defineRoute` threw and every route with a query schema answered 404. The
    validated query is now installed as an own property, which is what makes the
    schema's coercions survive into the handler.
  - **The query parser default changed** from `extended` to `simple`, which would
    have read `a[b]=1` as the literal key `a[b]`. Pinned back to `extended` so an
    upgrade here never silently changes how a caller's query string parses. A move
    to the narrower parser stays available as a deliberate change.
  - **A request with no body now arrives as `undefined`** rather than `{}`. Bodies
    are validated as `{}` when absent, so a body-less request still reports its
    missing fields instead of one opaque "expected object, received undefined", and
    `DELETE /admin/users` answers `User not found.` as before rather than throwing.
  - **The SPA history fallback route no longer parsed.** path-to-regexp v8 rejects
    a bare `*`, so `/console/*` is now the named `/console/*splat`.

  Route params are typed through a new `RouteRequest`, since Express 5 widens
  `req.params` to `string | string[]` for the repeatable params this API does not use.

- 429cfd2: Let a deployment choose which authenticators it will enrol.

  Adds the `authenticator_policy` system config key, settable from
  `AUTHENTICATOR_POLICY` as JSON:

  ```json
  { "attachment": "any" }
  ```

  `attachment` accepts `any`, `platform` or `cross-platform`. `any`, the default,
  offers both built-in authenticators and roaming security keys at registration,
  which is what an agency issuing hardware keys needs. Naming one narrows the
  browser picker for every registration on the instance.

  The `?attachment=` parameter on `GET /webauthn/register/start` still works, and
  is now bounded by the policy: a request asking for a kind a pinned policy
  excludes is refused with `400 { "error": "attachment_not_allowed" }` rather than
  silently overriding it. A request that agrees with the policy is fine.

  Existing deployments are unaffected. The key defaults to `{ "attachment": "any" }`,
  which is the behaviour they already had.

  Requires `@seamless-auth/types` 0.7.0, which carries the shared schema.

- fdbaa86: Record which authenticator a credential came from.

  Credentials recorded what an authenticator can do (transports, device type,
  backup state) but not what it is. The AAGUID that `@simplewebauthn/server` hands
  back at registration was discarded.

  It is now stored on the credential and returned on credential responses. That is
  the key the FIDO Metadata Service is looked up by, the key an allow or deny list
  of approved authenticators is expressed in, and what makes "which authenticator
  models are deployed here" answerable.

  An all-zero AAGUID is stored as reported rather than nulled. It means the
  authenticator declined to identify itself, which many platform authenticators do
  unless attestation is requested, and that is a different fact from never having
  recorded one.

  Existing credentials keep working and report no AAGUID. There is no backfill: the
  value was never captured and cannot be recovered from a stored public key.

  Requires `@seamless-auth/types` 0.12.0.

- 6512b4e: Answer a rate-limited request with the JSON error shape.

  Every other `4xx` and `5xx` on this API is `{ "error": "..." }`. A `429` was the one
  exception: express-rate-limit sends a string `message` through `res.send`, which lands
  as `text/html`, so a client parsing error bodies as JSON got a parse failure instead of
  an error.

  Three limiters set that string explicitly. The other six set no message at all and
  inherited the library's own string default, so they were plain text too. All nine sites,
  including the JWKS limiter, now send an object and answer:

  ```json
  { "error": "Too many requests, please try again later" }
  ```

  **Behaviour change:** the `429` body and its content type change. Two consumers were
  already coping with the text form rather than depending on it. `@seamless-auth/core`
  carries a `makeJsonTolerant` shim in `authFetch` that names this case in its comment,
  and `seamless-auth-react` was crashed by it once already. The admin dashboard maps `429`
  to fixed wording and never surfaces upstream text, so it is unaffected.

  The unreachable `message` on the slow-down is removed rather than converted.
  express-slow-down replaces the handler with one that only delays and calls `next`, so it
  never answers a request and that option could never be read.

- 3d21962: Stop an audit write failure from silently disabling account lockout.

  Failed attempts were counted by querying `auth_events`, whose writes swallow every
  error. Any condition that degraded audit writes while leaving the service running
  stopped failures being counted, so lockout silently stopped enforcing on every
  account while authentication carried on. Disk exhaustion, a table lock, a failed
  migration or connection pool exhaustion would all do it, and the absent records
  are the same absent records that would have shown it happening. The practical
  difference was a bounded versus an unbounded guessing attack against a numeric
  OTP.

  Failed attempts now go to their own `auth_failures` table, written separately from
  the audit event and read only by the lockout policy, so losing the trail no longer
  loses the control.

  `getUserLockoutStatus` refuses rather than guessing when it cannot read the
  counter: an authentication the server cannot vouch for gets the same `423` a
  locked account gets.

  Audit write failures are reported where monitoring already looks.
  `GET /health/status` answers `200 { "message": "System up, audit degraded",
"degraded": { "audit": { … } } }` for five minutes after one. The healthy body is
  unchanged, so anything already parsing it is unaffected, and the status stays
  `200` because the service is still serving. That is the defined action NIST
  800-53 AU-5 asks for; a log line nobody reads is not.

  Audit writes themselves still do not throw. 137 call sites await them, many from
  inside error handlers, so failing there would turn a bookkeeping failure into a
  failed request.

- bbb7fac: Report an unhandled server error as 500 rather than 404.

  The first error handler answered the CORS rejection and passed everything else on
  with a bare `next()`. Calling `next()` with no argument from an error handler clears
  the error and resumes at the next **regular** middleware, so the 500 handler directly
  below it was skipped and control landed on the 404. Any unhandled exception was
  therefore reported to the caller as `404 {"error":"Not Found"}`.

  Two consequences beyond the wrong status:

  - **Server faults were recorded against the caller.** The 404 handler logs an
    `AuthEventService.requestSuspicious` event with reason "Request to an unknown
    route." Every internal error was written into the anomaly signal the dashboard and
    the security views read, as suspicious behaviour by whoever happened to send the
    request. That stream is now free of them.
  - **Real errors were easy to miss.** A 500 is alertable. A 404 on an auth API is
    background noise, and this masked a genuine regression through a full test run.

  **Behaviour change:** a request that triggers an unhandled exception now answers
  `500 {"error":"Internal server error"}` instead of `404 {"error":"Not Found"}`. A
  genuinely unmatched route still answers 404, unchanged. Callers that retry on 5xx but
  not 4xx will now retry these. No dependent needed changing: the React SDK does not
  branch on 404, and the admin dashboard already maps `>= 500` to a clearer message than
  the 404 text it was getting.

- 7356602: Bound how many sessions one user may hold at once.

  `max_concurrent_sessions` defaults to no limit, so an instance that predates the
  setting is unaffected. Unlimited is `null` rather than `0`, and `0` is refused,
  because zero would otherwise read as "no sessions allowed" and lock every user
  out of a deployment that meant to remove the cap. `MAX_CONCURRENT_SESSIONS`
  accepts a number, or an empty value, `null`, `none` or `unlimited` for no cap,
  since a deployment template cannot easily unset a variable.

  At the limit a sign-in **succeeds** and the user's oldest session is revoked with
  `revokedReason: 'concurrent_session_limit'`, recorded as a new `session_evicted`
  auth event naming the session that ended. Refusing the new session instead would
  lock a user out of the device in front of them until something they may not have
  access to expires, which for the shared workstations this exists to protect is
  the common case rather than the edge one.

  Enforcement runs before the new session row is created, so the limit counts the
  session about to exist: at a limit of 3 a user holding 3 ends up with 3, not 4.
  Lowering the limit leaves users above it, and each converges on their next
  sign-in, which evicts everything above the cap in one pass. It never throws: a
  session that cannot be revoked is logged and the sign-in continues, because
  failing an authentication over a housekeeping step is worse than briefly
  exceeding the cap.

  NIST 800-53 AC-10. Requires `@seamless-auth/types` 0.17.0, which publishes the
  config key.

- 801f679: Let a magic link request choose where the link lands.

  The link was always built from one tenant-wide value, `frontend_url` falling back to
  the first configured origin. A tenant with both a web app and a mobile app could not
  serve both, because a link has to arrive in one or the other.

  `GET /magic-link` now takes an optional `redirectUri` query parameter. A supplied value
  is validated against the configured `origins`, exactly the way `resolveOAuthRedirectUri`
  already validates an OAuth redirect, and a value outside them answers `400`. The token is
  set as a `token` query parameter on the target, replacing one of that name the caller had
  already put there so the client is never handed two.

  **Additive.** Omit the parameter and the destination is unchanged, so no existing caller
  has to do anything.

  The redirect matching that OAuth had inline is now `src/lib/redirectAllowlist.ts` and
  shared by both flows, so an auth server has one place where "may we send someone here"
  is decided rather than one per flow.

  The allowlist is the WebAuthn `origins` list because there is no dedicated one. A
  destination that cannot be expressed as one of those, a custom scheme like `myapp://` or
  a universal link on a host that is not a WebAuthn origin, needs a
  `magic_link_redirect_uris` system config key. That key would live in
  `@seamless-auth/types` and needs a coordinated release, so it is deliberately left as a
  follow-up rather than bundled here.

- e47f16f: Stop the login request body downgrading a passkey-only policy.

  `POST /login` accepts a `passkeyAvailable` hint so a client without WebAuthn
  support is offered something it can actually complete. That hint was folded into
  the decision about whether passkey was usable at all, and the passkey-only branch
  was gated on the result. So a caller sending `passkeyAvailable: false` skipped
  that branch and was offered `magic_link`, `email_otp` and `phone_otp` instead,
  which turned off `passkey_login_fallback_enabled: false` from the request body.
  The one setting whose job is to keep a passkey-holding account on passkeys could
  be switched off by the account's own client.

  The hint is now advisory, which is all a self-reported capability can safely be.
  It can remove passkey from a set the policy already permits, and it cannot add a
  weaker method to a passkey-only one.

  **Behaviour change.** With `passkey_login_fallback_enabled: false`, an account
  that holds a passkey is now offered passkey only, whatever the client reports. A
  browser that genuinely cannot run the ceremony cannot sign in to such an account,
  which is what passkey-only means: the previous behaviour offered email OTP to
  anyone who claimed not to support passkeys. Accounts with no passkey are
  unaffected and keep the configured methods.

  This also closes a quieter version of the same problem. The React SDK computes
  the hint asynchronously and starts from `false`, so a user submitting before that
  check resolves, or hitting the error path, sent `passkeyAvailable: false` from a
  perfectly capable browser and was silently dropped to a weaker method.

- 606b1a4: Advertise every credential algorithm the FIDO specification requires.

  Registration relied on the SimpleWebAuthn default of `[-8, -7, -257]`, which
  omits `RS1`. FIDO Server Requirements v2.3 requires a server to implement `RS1`,
  `RS256`, `ES256` and `EdDSA`, so a conformance run would have flagged it.

  The set is now stated explicitly and ordered by preference, with `RS1` last.
  `pubKeyCredParams` is an ordered preference list, and `RS1` is
  RSASSA-PKCS1-v1_5 with SHA-1: it is offered because the specification requires
  support for it, and placed last so that no authenticator with a better option
  available will choose it.

  Verification is pinned to the same set. It previously fell back to every
  algorithm the library knows, which meant accepting a credential using something
  this server never offered.

  Stating the set also means a library upgrade cannot quietly change what is
  advertised, which a test now pins.

### Patch Changes

- 7ee36cf: Scan, describe and sign the published container image.

  Adopters pulling `ghcr.io/fells-code/seamless-auth-api` had no way to verify what
  was inside a tag or that it came from this repository. The release workflow now:

  - Builds the image and scans it with Trivy **before** it is pushed, failing on
    fixable high or critical findings, and reports the findings to the security tab
  - Attaches an SPDX SBOM and a provenance attestation to the image, so the
    registry can answer what is inside a tag and where it was built
  - Signs the pushed digest with cosign, keyless, so there is no signing key to
    store or rotate
  - Prints the digest and the exact verification commands to the job summary

  Unfixed findings do not block, and neither do npm's own bundled dependencies
  inside the Node base image, which the container never invokes and which no change
  here can patch. Verified against `node:24-slim`: without that exclusion the gate
  fails on four findings in npm's own tree on the first release. The application's
  own dependencies are still scanned and still block, which is the part this
  repository controls. A gate that blocks on something nobody can fix only trains
  people to bypass it.

- 9e420c8: Drop the vestigial `users.challenge` and `users.challengeContext` columns.

  WebAuthn challenges moved to the `webauthn_challenges` table, which gave them a
  purpose, an expiry and one-time use. These two were left behind so that release
  could be rolled back without losing challenge state, and nothing has read or
  written either since. Left in place they read as live state to anyone opening
  `src/models/users.ts`.

  The `down` restores both nullable, which is the shape they had. It does not
  restore data and does not need to: a challenge lives 300 seconds, so anything a
  rollback could carry across has already expired, and the worst case is an
  in-flight ceremony that the user starts again.

- b3ceae2: Keep the package pre-1.0 until cutting 1.0 is a decision.

  Two changesets asked for a major bump, which would have released 1.0.0 as a side
  effect of landing a breaking change rather than because the code was judged ready
  for it. Both are now minor, which under 0.x already signals a break, and both keep
  the breaking-change warning in their body where it does the reader some good.

  A CI check fails the build on any major changeset, so the next breaking change
  cannot quietly reintroduce this. Delete that check in the same change that cuts
  1.0.

- 5efcf5c: Load the conformance metadata statements the FIDO tools actually ship, and let
  their attestation statements validate.

  Two defects in conformance mode, both found by the first real run of the FIDO2
  Conformance Test Tools:

  - **Statements were never loaded.** The tools' "DOWNLOAD SERVER METADATA" archive
    unzips to a nested `metadataStatements/` directory, and the loader only read
    JSON files at the top level of `FIDO_CONFORMANCE_METADATA_DIR`. It silently
    found none. With `requireKnownAuthenticator` set, the metadata service runs in
    strict mode, so every conformance authenticator was refused as unlisted and
    every registration failed. The loader now recurses, so the archive can be
    dropped in unedited as the documentation already promised.
  - **Vendor attestation roots blocked their own tests.** The tools sign Apple,
    Android Key and SafetyNet statements with their own test roots, so validating
    them against the real vendor roots could never succeed. Those preset roots are
    now cleared in conformance mode, which lets the library fall back to the roots
    carried in the metadata statement.

  - **Registration options advertised an extension nobody asked for.**
    `generateRegistrationOptions` always appends its own `credProps`, and the tools
    compare the echoed extensions to the requested set for exact equality, so a
    request for `{"example.extension.bool": true}` came back as that plus
    `credProps` and failed. The requested set is now echoed verbatim. The
    authentication options path never had the problem, since the library passes
    extensions through there unchanged.

  All three are confined to `FIDO_CONFORMANCE_MODE`, which is refused under a
  production `NODE_ENV`. No deployed behaviour changes.

- 5ccced6: Derive the default authenticator policy from the schema instead of restating it.

  `SYSTEM_CONFIG_DEFAULTS.authenticator_policy` listed each field by hand, so a
  field added to `AuthenticatorPolicySchema` upstream stayed absent here until
  somebody noticed. That is not hypothetical: it is how the default fell behind
  when the schema gained `attestation` and `requireKnownAuthenticator`, and again
  when it gained `syncedPasskeys`, `aaguidAllowList` and `aaguidDenyList`.

  Parsing the schema with no input yields exactly the same object it produced by
  hand, so nothing changes today. What changes is that the next field arrives with
  the default the schema gives it rather than silently missing, and a test now
  fails if the two ever disagree.

- d0514db: Stop untrusted values reaching the log and the audit trail intact.

  Log messages interpolate request paths, provider ids and similar caller-supplied
  values through template strings across the codebase. A newline in one of those
  let a caller forge a second log entry. Control characters are now escaped
  centrally in the logger format, the single place every line already passes
  through for redaction, rather than at each call site where one missed
  interpolation reopens it.

  `redactSensitiveValue` built its output on a plain object, so a `__proto__` key
  in audit metadata hit the prototype setter instead of creating a property: the
  key vanished from the redacted output unredacted, and replaced that object's
  prototype with caller-supplied content. The output is now built on a null
  prototype, so the key is recorded as ordinary data.

  Dev signing key generation checked for a key file and then wrote one, so two
  processes starting together could both generate and both write, leaving one
  signing with a key that was neither on disk nor published in JWKS. Both paths
  now create the file exclusively and adopt the winner's key on losing the race.

  The slug trim matches a single leading or trailing dash rather than a run. The
  preceding collapse leaves no two dashes adjacent, so a run cannot occur, and
  matching one made the trim backtrack over an input of many dashes for a
  repetition that was never there.

- 682de10: Stop the test suite failing on assertions unrelated to the change under test.

  `vi.clearAllMocks()` in each spec's `beforeEach` empties call history but leaves
  the `mockResolvedValueOnce` queue intact, so a value queued by one test and never
  consumed was returned to a later, unrelated one. That shifted every subsequent
  queued value by a place, surfacing as a wrong status, a wrong body, or a request
  that never settled and timed out. Vitest now resets mocks between tests, which is
  what drains the queue.

  `vi.stubEnv` and `vi.stubGlobal` write to the process rather than the module
  registry, and `isolate` does not roll those back between files, so a stubbed
  `NODE_ENV` or a stubbed global `fetch` outlived the file that set it. Both are
  now restored automatically. `APP_ORIGINS` moved from a stub in `mocks.ts` to a
  plain assignment in `env.ts`, since restoring stubs before every test would
  otherwise drop it after the first test of each file.

  Route handlers answer the request before their fire-and-forget audit logging
  settles, so supertest resolved with continuations still queued and a stray call
  could land in the middle of the next test, breaking a `toHaveBeenCalledTimes` or
  a `toHaveBeenNthCalledWith` on a shared mock. Those are now drained after every
  test.

  With the leaks closed, spec files no longer have to run one at a time:
  `fileParallelism` is back on and the suite runs in about a sixth of the time.
  `npm run coverage` no longer forces sequential execution either.

- 52503b3: Resolve the high severity advisories in the dependency tree.

  `npm audit fix` cleared six high severity findings, all transitive, with no
  change to `package.json` and no change in behaviour. Two moderate advisories
  remain from `sequelize`, whose only offered fix is a downgrade to version 3.

## 0.7.4

### Patch Changes

- 7b8b6c2: Add `TRUST_PROXY` so the client address can be read from `X-Forwarded-For`.

  Express leaves `trust proxy` off by default, so behind a load balancer `req.ip` resolved to the
  balancer rather than the caller. Every client shared one bucket in the global rate limiter and the
  slow-down middleware, and `express-rate-limit` logged an `ERR_ERL_UNEXPECTED_X_FORWARDED_FOR`
  validation error on each request. Set `TRUST_PROXY` to the number of proxies in front of the server
  (`1` behind a single load balancer) to restore per-client limiting. It stays unset by default
  because a directly reachable server that trusts the header lets a client forge its own address.

## 0.7.3

### Patch Changes

- 9c379b0: Drop the orphaned bootstrap secret check from the container entrypoint.

  `validateEnvs.sh` still required `SEAMLESS_BOOTSTRAP_SECRET` whenever `SEAMLESS_BOOTSTRAP_ENABLED`
  was `true`. Both variables were removed with the admin bootstrap invite flow, so nothing in the
  runtime reads either one. A deployment that carried the old `SEAMLESS_BOOTSTRAP_ENABLED=true` over
  from a previous release refused to boot until it supplied a secret that no longer did anything.

## 0.7.2

### Patch Changes

- 892e616: Raise the default `refresh_token_ttl` from `1h` to `1d`.

  `refreshTtl` is the lifetime the server adapter gives the refresh cookie, so a one hour fallback
  capped the whole session at one hour no matter how active the user was. An app that holds state
  locally and makes no API calls for a couple of hours (a long form, for example) could not refresh
  afterwards, so the first save returned 401 and the work was lost. The session row itself already
  lives one day (`computeSessionTimes`), so the old fallback also under-reported the real refresh
  window.

  This changes runtime behavior for any deployment that relied on the fallback or on the shipped
  `1h` example value. Refresh tokens are rotated on use and stored hashed, so the longer lifetime is
  consistent with the existing session model. Set `REFRESH_TOKEN_TTL` (or the `refresh_token_ttl`
  system config row) to keep a shorter window.

  The bundled `.env.example` and compose files now ship `REFRESH_TOKEN_TTL=1d` to match.

## 0.7.1

### Patch Changes

- 381d87e: Send the registration response's `ttl` as a number.

  It was the string `'300'`, the only `ttl` this API sends that was not a number. A caller sets its
  registration cookie from it, and the Fastify adapter passes the value to a cookie library that
  requires an integer, so registration failed there with `TypeError: option maxAge is invalid: 300`.
  The Express adapter multiplies it into milliseconds, which coerces the string, so the same response
  worked and the mismatch went unnoticed.

  Requires `@seamless-auth/types` 0.6.0, where `RegistrationSuccessSchema.ttl` becomes a number.
  Response bodies are validated against that schema at runtime, so the two move together.

## 0.7.0

### Minor Changes

- 6bd56c4: Serve the publicly visible system configuration from an unauthenticated `GET /system-config/public`.

  It returns the configured `loginMethods` and nothing else. The bundled sign-in screens in the SDKs
  render before anyone has a session, so they cannot read the configuration and today fall back to a
  hardcoded list of methods. That list can advertise a method an instance has turned off. This lets a
  client ask instead.

  It also unblocks offering a skip on passkey registration, which is only safe when another login
  method is enabled. A client that cannot see the method list cannot make that call safely.

  The handler reads through `getLoginPolicy`, so a tainted or partially written config answers with
  the defaults rather than failing. A signed-out client with no methods has nothing to render, and a
  500 here would take the sign-in screen down with it.

  Every other key in the system configuration stays behind the admin routes.

## 0.6.0

### Minor Changes

- d248f4e: Make scoped admin roles assignable and discoverable.

  `POST /admin/users` and `PATCH /admin/users/:userId` now reject any role that is not in
  `available_roles` with `400 Invalid roles`, naming the offending roles in `details.roles`.
  Previously a typo like `admin:reed` was accepted and stored, granted nothing because enforcement
  never matches an unlisted role, and reported no error. The match is exact, so wildcards and deeper
  scopes must be listed to be handed out. An empty or unreadable role catalog skips the check rather
  than rejecting every assignment.

  `PATCH /admin/users/:userId` previously returned its `400` through a schema that stripped
  `details`, so the caller could not see what was rejected. Both user endpoints now use a validation
  error schema that carries it, and `POST /admin/users` declares its `400` and `409` responses in
  OpenAPI.

  The `OWNER_EMAIL` grant is now `admin:write` rather than a bare `admin`, stating the owner's
  authority in the scoped vocabulary. Instances whose `available_roles` lists only `admin` still get
  `admin`, which is equivalent in power, so the grant never becomes a no-op.

  `.env.example` now ships `admin:read` and `admin:write` in `AVAILABLE_ROLES` so the console's role
  picker offers read-only admin. `AVAILABLE_ROLES` seeds `available_roles` on first boot only, so
  existing instances need the scoped roles added through the admin system-config endpoints.

- 28d6c22: Support TLS to Postgres. `DB_SSL` (`true`/`false`, or an `sslmode` value such as `require` or
  `verify-full`) and an `sslmode` query parameter on the connection string now set Sequelize's
  `dialectOptions.ssl`, and `DB_SSL_CA` supplies a server CA bundle as inline PEM or a file path.
  Certificate verification follows libpq semantics: `require` encrypts without verifying, `verify-ca`
  and `verify-full` verify, and supplying a CA bundle turns verification on. `DB_SSL_REJECT_UNAUTHORIZED`
  overrides it either way. TLS stays off by default.

  `DB_URI` is now accepted as an alias for `DATABASE_URL`. Connection and TLS resolution is shared
  between the running app and the startup migrations, so a connection string configured without the
  discrete `DB_*` variables no longer breaks migrations.

- 7932ec7: Adopt `@seamless-auth/types@0.4.0` as the source for the shared contract. 88 schema definitions
  across 30 files become re-exports, removing roughly 900 lines of definitions this repo maintained
  in parallel with the SDKs, the dashboard, and the CLI. `roleGrantsAccess`, `hasScopedRole`, and
  `ROLE_NAME_PATTERN` now come from the package too, and the local transport widening shim added
  alongside the passkey fix is gone since the shared `TransportSchema` carries the full WebAuthn set.

  Two response shapes change as a result:
  - Organization and membership `createdAt`/`updatedAt` were `z.any()` and are now typed ISO
    date-times and required. They were always sent; they are now documented accurately.
  - `magic_link_email` delivery marks `token` optional, and anomaly events mark `type` optional,
    matching the shared schemas. Both are still always present in responses.

  Several schemas stay local because the shared versions would lose behavior: the pruned auth event
  list and the query filter built on it, the interval-aware metrics window cap, the timeseries
  `total`/`categories` fields, the grouped-summary `outcomes`, the OTP and magic-link success
  envelope that carries `token` and `delivery`, PRF salt validation, role assignment validation, and
  the JWKS and health responses that no other repo consumes. Each is commented with why.

- 5ecd1f2: Give `POST /login` a single rejection shape and record the server's security posture.

  Every `/login` failure now answers an identical `401 { "error": "Not Allowed" }`. An unknown
  identifier, an unverified account, an account with no permitted continuation method, and a failure
  to mint the pre-auth token previously produced three distinguishable bodies, so an unauthenticated
  caller could tell which case it had hit. The reason is still recorded in the `login_failed` auth
  event metadata, so operators keep the detail.

  The two identifier-lookup failure branches, which fire when the database is unreachable rather
  than when the identifier is unknown, answered `401` on the email path and `403` on the phone path.
  Both now answer `500 { "error": "Server error" }`, so an outage is reported as an outage instead
  of as a failed login.

  `loginMethods` is unchanged on the success response. Removing it buys no enumeration benefit until
  unknown identifiers also receive a decoy token, and dropping it early would degrade legitimate
  clients to a default method list.

  New `docs/security-posture.md` states the deliberate tradeoffs and their mitigating controls: the
  residual enumeration on `/login` and what closing it would take, ephemeral token replay within its
  5 minute TTL, email and phone being plaintext at rest, and the per-deployment `aud` scheme.

- 8ebdc2e: Standardize the error response shape. Every `4xx` and `5xx` response now carries a required
  `error` string, with `message` reserved for optional extra detail, so a consumer reads one field
  to learn why a call failed.

  25 handlers across the WebAuthn, user, internal metrics, dashboard, and security endpoints
  returned `{ message }` with no `error`. They now set `error`. Eight error responses on the
  `/internal/*` routes were declared with `MessageSchema`, which has no `error` field and would have
  stripped it; they now use `ErrorSchema`.

  `InternalErrorSchema` was a byte-identical duplicate of `ErrorSchema` and is now a deprecated alias
  of it. Nothing changes on the wire for the 53 routes that reference it.

  Success responses are untouched: `{ "message": "Success" }` on a `200` is a success payload, not an
  error body.

  A new conformance test walks every registered route and fails if a failure response declares a
  schema without a required `error` string, so a new route cannot reintroduce the split.

- ecaee6b: Prune auth event types that nothing emits, and fix the consumers that searched for them.

  15 of the 74 declared types had no emit site anywhere in `src/`. Five of them were actively
  queried by the security anomaly detector (`bearer_token_failed`, `jwks_failed`, `otp_failed`,
  `recovery_otp_failed`, `user_data_failed`), so those failure categories always returned nothing,
  while `verify_otp_failed`, `totp_failed`, `magic_link_failed`, and `logout_failed` were emitted and
  never searched for. The admin event filter had the same problem: `otp` expanded to a type nothing
  emits and missed every `verify_otp_*` and `mfa_otp_*` event, and `suspicious` named two types that
  are never written.

  Removed: the `bearer_token_*` and `jwks_*` families, `recovery_otp_*`, `user_data_failed`,
  `user_data_success`, `otp_failed`, `mfa_otp_suspicious`, `service_token_suspicious`, and
  `webauthn_login_suspicious`.

  The failure and suspicious groupings are now derived from `AUTH_EVENT_TYPES` instead of being
  hand-copied, so adding an event type files it in the right bucket automatically. A test asserts
  every declared type has an emit site, which is what would have caught the removed `bootstrap_admin_*`
  entries when that feature went away.

  Reading historical rows is unaffected: stored events are returned as `z.string()` and the query
  filter accepts any string, so events recorded under a removed name still appear.

- f7f95dc: Broaden the internal metrics endpoints beyond login success and failure.

  Auth event types are now rolled up into mutually exclusive categories (`suspicious`, `login`,
  `registration`, `webauthn`, `oauth`, `magicLink`, `otp`, `totp`, `stepUp`, `token`, `system`,
  `other`). Previously the grouping matched on substrings in order, so `webauthn_login_success` and
  `oauth_login_success` were counted as plain logins and never appeared in their own buckets.
  - `/internal/auth-events/timeseries` buckets now carry `total` and a `categories` map.
    `success` and `failed` stay login-only, so existing dashboards keep working.
  - `/internal/auth-events/grouped` returns the new categories in `summary` plus an `outcomes`
    roll-up, counts in the database instead of loading every auth event into memory, and accepts
    `from`, `to`, and `userId`.
  - `/internal/auth-events/login-stats` and `/internal/auth-events/summary` accept the same
    `from`, `to`, and `userId` filters as the other metrics endpoints.

  Two date-window fixes: the timeseries used to validate `from`/`to` and then return a now-relative
  window anyway (and with `interval=day` it queried only the last 24 hours while filling 30 daily
  buckets). Buckets now span the requested window. The maximum window is also capped per interval,
  31 days for `hour` and 366 days for `day`, and an open-ended window is measured against the
  current time rather than being unbounded.

- ddf9b41: Generate a real typed client from OpenAPI. `src/generated/api.ts` was an empty
  openapi-typescript stub (`paths = Record<string, never>`) with no way to regenerate it. It now
  carries the full contract, generated from the live route definitions along with a committed
  `openapi.json`.

  `npm run generate:api` produces both. It loads the route modules into a throwaway Express app to
  populate the OpenAPI registry, so no server, environment, or database is needed, and it refuses to
  write an empty spec. Output is prettier-formatted so regenerating never leaves the tree failing
  `format:check`.

  Both artifacts are covered by a test that rebuilds the document and compares it to what is
  committed, so a route or schema change that is not regenerated fails CI instead of silently
  drifting. The comparison ignores `info.version`, which tracks `package.json` and is bumped by
  Changesets on release.

- b3cb4d3: Add a one-command local stack. `docker compose up` now brings up Postgres and the published API
  image together with development defaults, so trying the project no longer means setting up
  Postgres, writing a `.env`, and generating secrets by hand. Migrations run on first boot, a
  development signing keypair is generated, and the admin console is served at
  `http://localhost:5312/console`. `OWNER_EMAIL` defaults to `owner@example.com`, so signing up with
  that address gives a working admin.

  The previous source-built stack moved to `docker-compose.dev.yml` for contributors. It no longer
  requires a `.env` file (one is used when present, and its values win) and it no longer depends on
  a prior `npm run build`, which meant it could not start from a fresh clone. A new `dev:container`
  script runs the watcher without `--env-file`.

  Neither compose file pins `container_name` any more, so a leftover container from an older stack
  no longer blocks startup.

- 81d8ea5: Ship admin dashboard v0.4.0 in the API image.

  `SEAMLESS_ADMIN_DASHBOARD_REF` moves from v0.3.0 to v0.4.0, so the SPA served at `/console` picks
  up that release. It brings keyboard and screen-reader operability across the app shell and charts,
  a step-up path for admins with no passkey, editable organization memberships, inline validation and
  unsaved-changes warnings in system configuration, refresh and export on monitoring, and fixes to
  the user directory, the events view, and sign-in failure messaging.

  The ref is a release tag rather than a floating branch, so the dashboard only changes when this
  value does.

- e9c10b1: Remove the admin bootstrap invite flow. `POST /internal/bootstrap/admin-invite` is gone, along with
  the `bootstrapToken` field on `POST /registration/register`, the `bootstrap_invite_email` external
  delivery kind, the `bootstrap_admin_granted` and `bootstrap_admin_check_skipped` auth event types,
  and the `SEAMLESS_BOOTSTRAP_ENABLED`, `SEAMLESS_BOOTSTRAP_SECRET`, and `SEAMLESS_AUTH_DEBUG_SECRETS`
  environment variables. A migration drops the `bootstrap_invites` table.

  The first admin is now granted through `OWNER_EMAIL`: a user who signs up with a configured owner
  email receives the admin role on account creation.

### Patch Changes

- 81d8ea5: Prune unused dependencies and clear the fixable audit findings.

  Removed three declared dependencies that nothing in the repo imports: `@sequelize/postgres`
  (an alpha of the Sequelize v7 rewrite, which sat in `dependencies` next to `sequelize@6` and
  shipped to the runtime image), `@types/bcrypt` (the code uses `bcrypt-ts`, which carries its own
  types, and a types package does not belong in production dependencies), and `ts-node` (everything
  runs through `tsx`). The production dependency tree drops by 38 packages.

  `tsx` moves to `^4.23.1`, which takes `esbuild ~0.28.0` and so resolves the patched `esbuild`
  0.28.1, and the `allowScripts` pin follows it. Together with `npm audit fix`, this clears the
  `esbuild`, `fast-uri`, `js-yaml`, `tar`, and nested `minimatch` advisories.

  `@types/node` moves to `^24.10.1` to match the `>=24 <25` engine and the pinned Node 24 runtime,
  and `@eslint/js` moves to `^10.0.1` to line up with the already-installed ESLint 10. The ESLint 10
  recommended set adds `preserve-caught-error`, which the log-and-rethrow sites in `src/lib/token.ts`
  and `src/utils/otp.ts` already satisfy, so enabling it needs no further source changes.

  Two advisories are knowingly left in place because neither has a non-breaking fix. `sequelize-cli`
  6.6.5 (the latest) still depends on `js-beautify`, which reaches a vulnerable `brace-expansion`;
  pinning `brace-expansion` to the patched 5.0.8 is not viable because its CJS entry exports
  `{ expand }` while the `minimatch@9` in that chain calls the default export, which would break
  migrations at container start. `sequelize@6` pins `uuid ^8`, and the `uuid` advisory covers only
  `v3`/`v5`/`v6` with a `buf` argument while Sequelize uses `v1` and `v4`, so it is not reachable.

- 870c370: Stop truncating passkey transports. A cross-device passkey reports `hybrid`, older Chrome reported
  `cable`, and security keys can report `smart-card`, but the credential serializer filtered
  `transports` down to the pre-hybrid `usb`/`ble`/`nfc`/`internal` set before building the response.
  Those credentials reported an empty transport list to every client, including `/users/me` and the
  admin user detail view.

  Stored data was never affected: the column is unconstrained JSON and registration writes the value
  through verbatim, so the correct transports come back as soon as the read path stops dropping them.
  No migration or backfill is needed.

  `CredentialResponseSchema` carries a local override widening `transports` to the full WebAuthn set,
  because `@seamless-auth/types@0.1.3` still declares the narrow one. The override and
  `src/lib/authenticatorTransports.ts` can both be deleted once the widened types release is adopted.

## 0.5.0

### Minor Changes

- 96e8797: Auto-grant the admin role to a user who signs up with an `OWNER_EMAIL` address.
  Managed instances are provisioned with `OWNER_EMAIL` (the tenant owner, optionally
  a comma separated list); when that user first registers (email/OTP) or signs in
  through a verified OAuth profile, they receive the `admin` role in addition to the
  default roles, provided `admin` is an available role. This makes the bundled
  `/console` admin dashboard usable on a freshly provisioned instance without a
  separate bootstrap-promotion step. The grant is a no-op when `OWNER_EMAIL` is
  unset, so non-managed deployments are unchanged, and it only ever applies to an
  email whose control the signup flow has already verified.

## 0.4.0

### Minor Changes

- 7ea0a9d: Add a `DISABLE_AUTH_RATE_LIMITS` testing escape hatch.

  Beyond the configurable global limiter (`RATE_LIMIT`), dedicated per-IP and
  per-identity limiters guard the OTP, magic-link, registration, and OAuth routes,
  plus JWKS. An automated test or conformance suite driving many of these flows from
  a single IP trips them. Setting `DISABLE_AUTH_RATE_LIMITS=true` now makes every
  auth limiter skip. It is refused under `NODE_ENV=production` (like
  `ALLOW_UNCREDENTIALED_DELIVERY_SECRETS`), so it can never weaken a deployed server.
  Defaults to off.

- 47282ee: Surface actionable OAuth callback failure codes.

  The OAuth callback previously collapsed every profile failure into a generic
  `400 { error: 'OAuth login failed' }`, so a user whose provider returned no email
  (the most common case, for example a GitHub account with no public email) had no
  way to know what to fix. The callback now returns a stable machine-readable `code`
  alongside the existing `error` string for the curated, user-actionable cases:
  `oauth_missing_email`, `oauth_email_not_verified`, and `oauth_missing_subject`.
  Unexpected internal failures still return the generic message with no detail, and
  the audit event records the specific reason instead of the blanket
  `callback_failed` for the known cases.

- 8c218c4: Make admin system-config writes authoritative so they survive a restart.

  Env-mapped `system_config` rows are re-seeded from their environment variable on
  every boot for any row whose `updatedBy` is `NULL`. Admin console writes went
  through the access-token path, which never populated `updatedBy` (only the
  service-token path did), so a change made in the console (for example adding an
  OAuth provider or enabling the `oauth` login method) was silently reverted on the
  next restart, contradicting the documented contract.

  The whole-config `PATCH /system-config/admin` and the per-provider
  `/system-config/oauth-providers` endpoints now record the acting admin's id in
  `updatedBy` on the access-token path, in addition to the existing service-token
  path, so an admin change is genuinely authoritative and is no longer overwritten
  from env. Boot now also logs a warning when it overwrites a stored value that
  differs from the env-derived one, so the reseed is no longer silent.
  `docs/configuration.md` is updated to describe the real precedence.

## 0.3.0

### Minor Changes

- fe78de9: Add admin routes to manage OAuth providers at runtime without hand-editing `system_config` or replacing the whole config array. New endpoints under the existing SystemConfig admin surface: `GET /system-config/oauth-providers` (list), `POST /system-config/oauth-providers` (add, 409 on duplicate id), `PATCH /system-config/oauth-providers/:id` (update, 404 on unknown id), and `DELETE /system-config/oauth-providers/:id` (remove, 404 on unknown id). Each route requires an admin access token (`requireAdmin('read')` for the list, `requireAdmin('write')` for mutations), validates against `OAuthProviderConfigSchema`, invalidates the system-config cache after writes, and records a `system_config_updated` audit event. Client secrets stay out of the API surface: providers continue to reference `clientSecretEnv` and the routes never accept or return a raw secret. Providers remain editable through the existing `PATCH /system-config/admin` whole-array patch, so this is additive.
- 916a3b7: Require a validated internal service token for external delivery in all environments. `canReturnExternalDelivery` no longer treats a non-production `NODE_ENV` as sufficient, so the `x-seamless-auth-delivery-mode: external` header must now be accompanied by an `x-seamless-service-token` that passes issuer, audience, and subject validation. `canReturnSensitiveDevelopmentDetails` is gated the same way. Local development that cannot present a service token can set `ALLOW_UNCREDENTIALED_DELIVERY_SECRETS=true`, an explicit opt-in that is ignored when `NODE_ENV=production`.
- 0005244: Serve the admin dashboard SPA at the `/console` subpath on the API's own origin. Static serving is additive and gated behind `SERVE_ADMIN_DASHBOARD` (enabled by default): the admin API routes are registered first and keep priority, and an SPA history fallback returns the dashboard `index.html` for unmatched `/console` and `/console/*` navigations, with correct MIME types, long-lived immutable caching for hashed assets, and `no-store` on the shell. `/console` is used instead of `/admin` so the SPA namespace never overlaps the admin API under `/admin/*`. The Docker image builds the dashboard from a pinned git ref (the `SEAMLESS_ADMIN_DASHBOARD_REF` build ARG) with base path `/console` and copies it into the runtime image. No CORS changes are needed because the dashboard is same-origin.

### Patch Changes

- 594df9b: Fix response schema handling so a controller response that fails its declared schema is no longer overwritten. Previously the API replaced the real body with a generic `Response validation failed` object and leaked internal Zod issues to clients. It now logs the drift server-side and returns the controller's intended response unchanged.
- ff8067d: Bind the `aud` claim on signed user tokens. `signAccessToken`, `signRefreshToken`, and `signEphemeralToken` now call `.setAudience(ISSUER)` in addition to `.setIssuer(ISSUER)`. The Seamless adapter verifies signed auth responses with `aud === audience`, and the deployment contract requires the adopter's `audience` to equal its `authServerUrl`, which is byte-identical to this server's `ISSUER`. Without the claim, jose rejects every token the adapter checks, so login, registration, OAuth, OTP, magic-link, and organization-switch all fail once the adapter's audience binding ships. The claim is additive and ignored by verifiers that do not check it.

## 0.2.7

### Patch Changes

- 7b33abc: Fix OAuth signup writing a synthetic `oauth:<provider>:<subject>` string into the user's phone field. New OAuth users now have a null phone since the provider supplies no phone number.

## 0.2.6

### Patch Changes

- 3cbc491: Build and run the Docker image on Node 24 (`node:24-slim`) to match the
  package's `engines.node` (`>=24 <25`). The image previously used `node:20-slim`,
  which triggered EBADENGINE warnings and could crash the container at startup,
  including in the CLI conformance harness.

## 0.2.5

### Patch Changes

- c71d182: Parse the `FRONTEND_URL` env var as a single string in `parseSystemConfigEnvValue`.
  The `frontend_url` system config was added to the env map and schema but never
  handled by the env parser, so bootstrap threw `Unhandled system config key:
frontend_url` whenever `FRONTEND_URL` was set. Document the variable in
  `.env.example`.

## 0.2.4

### Patch Changes

- f2e3faa: Build the magic-link redirect from a dedicated frontend URL. Add an optional
  `frontend_url` system config (env `FRONTEND_URL`) and use it as the base for
  emailed magic links, falling back to `origins[0]` when unset. Previously the
  link was always built from the first configured origin, which could point at a
  non-frontend origin (for example an API host) depending on origin ordering.

## 0.2.3

### Patch Changes

- 0201af6: Mark `GET /logout` as deprecated in the generated OpenAPI document.

  `defineRoute` now supports a `deprecated` flag that is forwarded to the OpenAPI
  operation. The legacy `GET /logout` route sets it, so consumers and generated
  clients can detect the deprecation and migrate to `DELETE /logout/all`. Runtime
  behavior is unchanged.

- 7d89315: Remove the legacy refresh-token fallback scan.

  Refresh-token lookup now resolves sessions solely by their indexed `refreshTokenLookup`
  fingerprint. The compatibility path that scanned all pre-fingerprint sessions and
  bcrypt-compared each hash on a lookup miss has been removed, along with its per-request
  `Session.findAll` scan. Sessions created before the `refreshTokenLookup` migration are no
  longer refreshable and must re-authenticate; such sessions are long past the refresh-token
  TTL, so no active sessions are affected.

- a236888: Rate limit the `POST /registration/register` endpoint.

  Registration now applies the same per-IP and per-identity limiters already used by
  the OTP and phone-registration routes. This closes an unthrottled path that allowed
  registration/OTP spam and account enumeration against the endpoint.

- ac309bb: Validate `system_config` on the runtime read path.

  `getSystemConfig()` now parses stored configuration against `SystemConfigSchema` on load
  instead of trusting the database rows with a cast. Invalid configuration fails loudly (the
  call throws and the error is logged) rather than flowing malformed values into auth logic.
  Also corrects the cache TTL comment (the value is 5 minutes, not 30 seconds).

## 0.2.2

### Patch Changes

- 03651ba: Harden and regression-test the magic link and OTP sign-in flows.
  - Magic link: polling while waiting now returns `204` (no body) instead of `500`,
    fixing the broken starter sign-in; removed dead device-binding code from verify
    (binding is enforced at the poll step); the post-session write is awaited.
  - OTP: the verify endpoints are now rate-limited; OTPs are stored and compared
    hashed-only (the transitional plaintext fallback is removed); post-session writes
    are awaited.
  - CI: formatting is enforced (`prettier --check`) and coverage thresholds are
    ratcheted so these flows cannot silently regress.

- 3292605: Env-mapped system config (e.g. `LOGIN_METHODS`) now takes effect over
  migration-seeded defaults. Previously the login-policy migration hard-seeded
  `login_methods` and `bootstrapSystemConfig` only seeded missing rows, so the env
  var was permanently ignored. Now bootstrap re-applies env values over config that
  was never changed through the admin API (`updatedBy IS NULL`), admin edits record
  `updatedBy` so they are preserved, and a migration re-applies env to existing
  un-edited rows.
- 6b6f1e6: Apply OAuthProviderConfigSchema defaults to providers configured via OAUTH_PROVIDERS. The
  env value was parsed with a raw JSON.parse, so per-provider fields like subjectJsonPath and
  emailJsonPath stayed undefined and OAuth profile extraction failed with a generic
  "OAuth login failed". The OAuth callback now also logs the underlying error. Fixes #49.

## 0.2.1

### Patch Changes

- 95d321f: Fixed an issue with passing non-valid tokens through to the auth server

## 0.2.0

- Current release baseline before Changesets-managed releases.
