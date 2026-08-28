# Certification Readiness

Engineering analysis of what Seamless Auth needs to change to be credible for
Maryland local government work, and to earn the two credentials the operating
plan targets: **FIDO Functional Certification (server)** and **GovRAMP**.

Companion to two internal documents that are not published in this repository:
the operating plan (which certifications, and in what order) and the client
migration runbook (what an engagement promises a client). Both live in the
private `fellscode` repository. This document is the technical half, and it is
the answer to the README's "What these imply for this repository" section.
References to those documents below are deliberate and will not resolve as
links here.

Drafted August 2026 against `seamless-auth-api` v0.7.4. Findings are cited to
file and line so they can be re-checked as the code moves.

The work is tracked in
[issue #155](https://github.com/fells-code/seamless-auth-api/issues/155), broken
into sessions. Two findings are tracked privately as security advisories rather
than public issues, per [SECURITY.md](../../SECURITY.md).

---

## 0. How this sits with the freeze

The freeze in the workspace `AGENTS.md` allows exactly four kinds of
development work. This document maps onto two of them, and the distinction
matters for sequencing:

| Freeze exception                                    | This document                                                                                                                                  |
| --------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| 3. FIDO conformance self-validation fixes           | **Fully in scope.** Part A is exactly this. It is the one credential earnable without a customer                                               |
| 2. Gaps identified by the GovRAMP Security Snapshot | **Specced here, not yet authorized to build.** The Snapshot has not been purchased. Part B is a prediction of what it will find, not a finding |

There is a third category this analysis surfaced that the freeze already
covers under exceptions 1 and 4: places where the **website and the runbook
promise behavior the code does not implement**. Those are in Part D. They are
not new features. They are the gap between what is being sold and what ships,
and each one is a live risk of failing in front of the first customer.

**Recommended reading of the freeze:** Part A and Part D are green. Part B
should be written down now (it is cheap) and built after the $1,500 membership
plus Single Security Snapshot, so remediation follows evidence instead of
guesswork. Buying the Snapshot is item 9 on the ranked list. Building Part B
before it is bought inverts the order the operating plan sets.

---

## Part A: FIDO Functional Certification (server)

### A.1 What the program actually requires

Precision here, because the operating plan is right that this is frequently
misstated. **Functional Certification** is the applicable program. It covers
protocol compliance and interoperability and applies to servers. Authenticator
Certification levels (L1 through L3+) apply only to authenticator hardware and
must never appear in Fells Code material.

The path for a server is:

1. **Conformance self-validation** using the FIDO2 Conformance Test Tools.
   Tool access comes with registration. This step can start today, without an
   assessor and without a customer.
2. **Interoperability testing**, at a proctored event or on-demand, which must
   happen **within 90 days** of a successful self-validation. Self-validation
   results must reach the Certification Secretariat at least 14 days before an
   interop event.
3. Certification submission with fees, then optional trademark license.

The normative requirements a server must meet are in FIDO **Server
Requirements v2.3** (WebAuthn Level 3 and CTAP 2.3).

### A.2 Gap analysis against the current implementation

All WebAuthn logic lives in
[src/controllers/webauthn.ts](../../src/controllers/webauthn.ts).

| Server Requirements v2.3 obligation                                   | Status      | Evidence                                                                                                                                        |
| --------------------------------------------------------------------- | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| MUST support Packed, TPM, U2F and Android SafetyNet attestation       | **Fail**    | `attestationType: 'none'` at [webauthn.ts:111](../../src/controllers/webauthn.ts#L111). Attestation is never requested and never verified       |
| MUST validate attestation certificate chains                          | **Fail**    | No chain validation anywhere                                                                                                                    |
| MUST support attestation validation through the FIDO Metadata Service | **Fail**    | No MDS integration. `grep -rin "MetadataService\|mds" src/` returns nothing                                                                     |
| MUST implement RS1, RS256, ES256, EdDSA                               | **Partial** | `supportedAlgorithmIDs` is never set, so the SimpleWebAuthn default `[-8, -7, -257]` applies (EdDSA, ES256, RS256). **RS1 (-65535) is missing** |
| MUST implement P-256 and Ed25519 curves                               | Pass        | Covered by the default algorithm set                                                                                                            |
| MUST use a fresh cryptographically random challenge per request       | Pass        | SimpleWebAuthn `generateChallenge()`, 32 bytes                                                                                                  |
| MUST validate assertion signatures, UP and UV flags                   | Partial     | Delegated to SimpleWebAuthn, but see the UV mismatch below                                                                                      |
| Conformance tools require a standard message interface                | **Fail**    | No conformance route surface exists                                                                                                             |

Three further issues that are not strictly conformance failures but will
either break testing or fail review:

**Challenge lifecycle on the authentication path.** There is a defect here that
is tracked privately as a security advisory rather than described in this
document, per [SECURITY.md](../../SECURITY.md). It is best fixed in the same
change as the challenge store work in A6. Anyone picking up A5 or A6 should read
the advisory first.

**A single challenge slot on the user row.** `users.challenge` holds one value,
so two concurrent flows for the same user clobber each other. Registration and
login use the same field.

**User verification is inconsistent between the two halves.** Registration asks
for `userVerification: 'preferred'` ([webauthn.ts:117](../../src/controllers/webauthn.ts#L117)),
authentication requires `'required'`. A credential enrolled without UV can be
created and can then never be used to sign in. For a government deployment
claiming phishing-resistant authentication, both should be `required`, and that
should be policy-driven rather than hardcoded.

### A.3 The good news on effort

`@simplewebauthn/server` 13.3.0 already ships everything the failures above
need. It is installed and unused:

- Every required attestation verifier is present under
  `esm/registration/verifications/` (packed, tpm, android-key,
  android-safetynet, apple, fido-u2f).
- A full MDS implementation is present under `esm/metadata/`
  (`verifyMDSBlob`, `verifyAttestationWithMetadata`).
- `MetadataService` and `SettingsService` are exported from the package root
  with `initialize()` and `getStatement(aaguid)`.
- `RS1` exists in the COSE algorithm enum.

This is wiring work, not cryptography work. That materially changes the cost
estimate.

### A.4 Work items

| #   | Item                                                                               | Size | Notes                                                                                                            |
| --- | ---------------------------------------------------------------------------------- | ---- | ---------------------------------------------------------------------------------------------------------------- |
| A1  | Add an `aaguid` column to `credentials` plus a backfill migration                  | S    | Prerequisite for A2, A3 and D2. [src/models/credentials.ts](../../src/models/credentials.ts) has no AAGUID today |
| A2  | Initialize `MetadataService`, verify attestation against MDS, store the result     | M    | Needs an offline cache and a fail-closed-or-open decision per agency                                             |
| A3  | Support `attestationType: 'direct'`, persist the attestation format and trust path | M    | Keep `'none'` as the default for consumer deployments; make it configurable                                      |
| A4  | Set `supportedAlgorithmIDs` explicitly, including RS1                              | S    | One line plus a test                                                                                             |
| A5  | Correct the challenge lifecycle on the authentication path                         | S    | See the private advisory. Worth doing regardless of certification                                                |
| A6  | Move the challenge off the user row into a keyed, TTL-bounded store                | M    | Fixes the concurrency clobber and gives a real expiry                                                            |
| A7  | Make `userVerification` policy-driven and consistent across register and login     | S    | Feeds the phishing-resistant mode in D4                                                                          |
| A8  | Add the conformance test interface behind an env flag, off by default              | M    | Must never be reachable in a production deployment                                                               |
| A9  | Run the FIDO2 Conformance Test Tools, fix what they surface                        | L    | Unknown until A1 through A8 land                                                                                 |

Realistically A1 through A8 are a couple of focused weeks. A9 is the unknown.
Register for tool access early, because the 90-day interop clock starts at
successful self-validation and the tools themselves will reveal work that this
analysis cannot predict.

---

## Part B: GovRAMP Security Snapshot readiness

The Snapshot scores 40 controls drawn from NIST SP 800-53 Rev. 5 and MITRE
ATT&CK, over a 28-day documentation window, with a score back in about three
weeks. The score is confidential unless Fells Code publishes it.

The single most useful thing about that structure: assembling artifacts for 40
controls is mostly a **writing** exercise, and this repo is unusually well
placed for it. [docs/security-posture.md](../security-posture.md) is already a
control-narrative document in everything but name, and
[docs/production-operations.md](../production-operations.md) has a secrets
inventory. That is a real head start on a System Security Plan.

What follows is the code-side gaps most likely to score badly. Predictions, not
findings.

### B.1 Audit and accountability (AU). The weakest family.

**AU-3, audit record content. The admin recovery event names the wrong person.**
`recoverUserForDeviceReplacement` logs the event with `userId` set to the
**target** user, and `metadata.targetUser` set to the same value
([admin.ts:511](../../src/controllers/admin.ts#L511)). The acting
administrator's identity is recorded nowhere. This is on the single most
sensitive endpoint in the product, the one that revokes every session, deletes
every passkey and disables TOTP. The audit trail says the victim did it to
themselves.

The runbook's Phase 5 commits to a "quarterly review of recovery requests,
looking for social engineering patterns." That review is not possible against
this data. Fix by adding an explicit `actor_user_id` to `auth_events` and
populating it on every administrative action.

**AU-5, response to audit logging process failures.**
`AuthEventService.logContext` catches write errors and continues
([authEventService.ts:61](../../src/services/authEventService.ts#L61)), so an
audit write failure is recorded to the application log but not otherwise acted
on. AU-5 requires a defined action on audit logging process failure. At minimum
this needs alerting and a deliberate, documented failure posture.

There is a further consequence of this design that is tracked privately as a
security advisory rather than described here, per
[SECURITY.md](../../SECURITY.md). Read it alongside this item, because it
changes how urgent the fix is.

**AU-9, protection of audit information.** `auth_events` is an ordinary table
with `beforeUpdate` and `beforeSave` hooks
([src/models/authEvents.ts](../../src/models/authEvents.ts)), so records are
updatable by anything holding the application's database credentials. There is
no append-only constraint, no hash chain, no write-once storage.

**AU-11, audit record retention.** No retention configuration, no archival, no
purge. `grep -rin "retention\|purge" src` finds only OAuth state cleanup. This
is open decision 8 in the runbook, and for Maryland it must map to state
records retention schedules rather than a product default.

**AU-4 and AU-6, storage capacity and review.** The Winston logger only attaches
a file transport when **not** in production
([logger.ts:43](../../src/utils/logger.ts#L43)). Production is console-only,
with no syslog or SIEM transport. There is also no audit export endpoint, which
the runbook's annual evidence package explicitly promises as "exportable audit
event history for the period."

**Correlation.** Auth events carry no `session_id`, so an event cannot be tied
to the session it happened in.

### B.2 Access control and session management (AC)

**AC-11 and AC-12.** Session lifetimes are hardcoded constants:
`MAX_SESSION_LIFETIME_DAYS = 1` and `IDLE_TIMEOUT_DAYS = 1`
([utils.ts:11-12](../../src/utils/utils.ts#L11)). Because they are equal, **the
idle timeout can never fire before absolute expiry**, so in practice there is no
idle timeout at all. Neither value is in `system_config`, so an agency cannot
tune them. Government idle timeouts are typically 15 to 30 minutes.

**AC-10, concurrent session control.** Not implemented. No cap on simultaneous
sessions per user.

**Credit where due.** Step-up authentication is implemented, has a five-minute
freshness window, and is correctly applied to the device replacement recovery
route ([admin.routes.ts:336](../../src/routes/admin.routes.ts#L336)). Scoped
admin roles with read and write separation exist in
[requireAdmin.ts](../../src/middleware/requireAdmin.ts). Refresh tokens are
bcrypt-hashed at rest with a separate HMAC lookup index. Metadata redaction
([src/utils/redaction.ts](../../src/utils/redaction.ts)) is genuinely thorough.
These will score well.

### B.3 System and communications protection (SC)

**SC-12 and SC-17, key management. Not implemented in production.** The
production branch of `ensureKeys()` is an empty function body with the comment
"Implement a first time JWKS rotation"
([keyManager.ts:53](../../src/scripts/keyManager.ts#L53)). There is no rotation
mechanism, no rotation schedule and no rotation runbook step.

**Secret storage.** `getSecret` reads `process.env` and nothing else
([secretsStore.ts](../../src/utils/secretsStore.ts)). No KMS, no secrets
manager, no envelope encryption. Workable for a small deployment, but it is a
question that will be asked.

**FIPS.** No FIPS 140-2 or 140-3 validated cryptographic module. Stock Node.js
crypto is not validated. This does not block GovRAMP Core, but it does bear on
CJIS and on any agency with a FIPS requirement, and the honest answer needs to
be written down before someone asks it on a call.

### B.4 Risk assessment, configuration and supply chain (RA, CM, SR)

CI runs lint, format, tests with coverage, typecheck and build
([.github/workflows/ci.yml](../../.github/workflows/ci.yml)). What it does not
run:

- No dependency vulnerability scanning. There is no Dependabot configuration in
  `.github/` and no `npm audit` step (**RA-5**, **SI-2**)
- No static analysis or CodeQL (**RA-5**)
- No SBOM generation (**SR-4**), no container image scanning, no image signing
  or build provenance (**SR-3**, **SR-11**)

These are the cheapest points on the board. Most are a single workflow file
each, and they are the kind of thing a Snapshot reviewer checks for first
because it is checkable.

### B.5 Identification and authentication (IA)

The default login policy is `login_methods: ['passkey', 'magic_link']`
([systemConfig.defaults.ts:10](../../src/config/systemConfig.defaults.ts#L10)).
Magic links are **not** phishing-resistant. A deployment left on defaults, sold
as phishing-resistant authentication, ships with a phishing-susceptible
fallback enabled.

`passkey_login_fallback_enabled` can suppress fallback when the user already has
a passkey, but there is no single enforceable "phishing-resistant only" mode,
and no way to produce evidence of it for an auditor. See D4.

---

## Part C: Maryland and general government expectations

### C.1 The Local Cyber Assessment Tool is the real near-term target

Maryland local governments self-assess against DoIT's NIST CSF-based Local Cyber
Assessment Tool, and the Maryland GTM is right that every jurisdiction has
either run it or been told to. It is more immediately useful than either
certification, because it is the instrument the buyer is already being measured
against.

The engineering implication is narrow and worth doing: the product should be
able to **produce the evidence** a jurisdiction needs to answer the tool's
identity and access control items. Concretely, an authentication coverage
report (how many staff are on phishing-resistant credentials, broken down by
department, with a trend) is the artifact that converts a posture report into a
renewal. It does not exist today.

### C.2 State Minimum Cybersecurity Standards

These bind Executive Branch state agencies, not local governments. That gap is
the GTM's stated opening and it does not create a direct product requirement.
It does set the bar locals will eventually be held to, so it is a reasonable
design reference.

### C.3 CJIS

Open decision 2 in the runbook, and the GTM notes it is a disqualification
question asked on the first call. From the code, the honest position today is
that a CJIS workload could not be supported without at minimum: FIPS-validated
cryptography, the audit integrity and retention work in B.1, and a documented
personnel screening and incident response process. **Settle this before the
first Phase 0 call, and settle it as "no, and here is why" unless the work in
B.1 and B.3 is funded.** Claiming otherwise is the one mistake the GTM says is
expensive.

### C.4 Records retention

Maryland jurisdictions operate under state records retention schedules.
Authentication audit events are records. Until AU-11 work lands, there is no
retention setting to align to a schedule, and no defensible deletion. This is
open decision 8 and it is a product requirement, not a policy preference.

### C.5 NIST SP 800-63B assurance levels

Nobody has asked for this yet, but AAL2 and AAL3 are the vocabulary a state
reviewer will use. Passkeys with UV can reach AAL2, and hardware authenticators
can support AAL3 claims. Being able to state, per deployment, which AAL the
configuration achieves is worth more in a procurement document than either
certification logo. It depends on D2 and D4 landing.

---

## Part D: Where the collateral promises what the code does not do

These are the highest-priority items in this document. Each is a place where
the website or the runbook commits to behavior the code does not implement.
They are in scope under freeze exceptions 1 and 4, and each is a live risk of
failing in front of the first customer.

### D1. Hardware security keys cannot be enrolled at all

`authenticatorAttachment: 'platform'` is hardcoded in the registration options
([webauthn.ts:119](../../src/controllers/webauthn.ts#L119)). That restricts
enrollment to platform authenticators (Touch ID, Windows Hello, Android
biometrics) and **excludes roaming authenticators entirely**, which means USB
and NFC security keys cannot be registered.

Appendix B of the runbook, which mirrors the `/migration` page, gives these as
the standard answers for the hard cases:

| Case                          | Promised pattern                                          |
| ----------------------------- | --------------------------------------------------------- |
| No agency phone               | "Issued hardware security key on lanyard or keyring"      |
| Shared front-desk workstation | "Per-person roaming keys against a shared device profile" |
| Lost key                      | "Spare key policy means most staff never need either"     |

**None of these are possible today.** These are precisely the hard cases that
distinguish a government pitch from a consumer one, and they are the ones a
school system or a public works department will ask about first. This is the
most important single line of code in this document.

Fix: make attachment a per-deployment policy with a user-selectable path at
enrollment, defaulting to unrestricted.

### D2. Synced passkeys are not blocked, contrary to the stated design position

The public-sector README records the design position as "blocked by default,
agency may enable" and asks that it be confirmed against actual behavior.

**Confirmed: it is not implemented.** The `credentials` table stores `backedup`
([credentials.ts:19](../../src/models/credentials.ts#L19)), which is the
WebAuthn backup state flag, but nothing ever reads it to make a decision. There
is no AAGUID column, so there is no authenticator allow-list or deny-list
either. Any synced consumer passkey enrolls successfully.

This also blocks a related requirement that will come up in Maryland: agencies
that want to restrict enrollment to FIPS-validated authenticators cannot,
because that policy is expressed by AAGUID.

Fix depends on A1 (AAGUID) and A2 (MDS), which is a good reason to do Part A
first. The website text should be corrected to match reality in the meantime.

### D3. Recovery does not record how identity was proofed

The runbook commits to in-person identity-proofed recovery as the default, with
a documented remote exception. `DeviceReplacementRecoverySchema` accepts only
`revokeSessions`, `removePasskeys` and `disableTotp`. There is no field for the
proofing method, the evidence seen, or the approver.

So the API cannot enforce the policy, cannot record compliance with it, and
cannot produce evidence of it. Combined with the AU-3 attribution bug in B.1,
the most sensitive operation in the product is also the least auditable one.

Fix: add required proofing fields to the recovery payload and persist them on
the audit event alongside `actor_user_id`.

### D4. Session lifetime cannot be tuned to the shift

Appendix B promises "session lifetime tuned to the shift, not to a policy
default" for field and vehicle devices. Both lifetime constants are hardcoded to
one day and are not in `system_config` (B.2). The promise cannot be kept.

Fix: move both into `system_config`, per organization if the tenancy model
allows it.

---

## Part E: SDK and ecosystem blast radius

Per the ripple protocol in [CLAUDE.md](../../CLAUDE.md), most of this work is
contract-affecting. Specifics:

**`@seamless-auth/types`.** `SystemConfigSchema` gains keys for session
timeouts, authenticator policy (attachment, AAGUID allow-list, synced passkey
posture), user verification policy, and audit retention. Needs a version bump
and a coordinated release across this API and both SDKs.

**`seamless-auth-server` (adapter).** New routes need explicit passthrough in
**three** places, and missing any one of them silently 404s:

- [packages/core/src/ensureCookies.ts](../../../seamless-auth-server/packages/core/src/ensureCookies.ts)
- [packages/express/src/createServer.ts](../../../seamless-auth-server/packages/express/src/createServer.ts)
- [packages/fastify/src/routes/adminRoutes.ts](../../../seamless-auth-server/packages/fastify/src/routes/adminRoutes.ts)

Affected by: the audit export endpoint (B.1), the coverage report (C.1), and
the extended recovery payload (D3).

**`seamless-auth-react`.** `createSeamlessAuthClient` passes server-provided
options straight into `startRegistration` and `startAuthentication`, so
attestation and attachment changes flow through without SDK edits. What does
need SDK work is the **user-facing enrollment choice** for D1: a "use a security
key instead" path, which is new surface rather than a passthrough.

**`seamless-auth-admin-dashboard`.** Consumes auth events. Adding
`actor_user_id` and `session_id` is additive, but the dashboard should surface
the actor on admin actions or the fix delivers no operational value.

**`seamless-cli`.** Runs the cross-repo conformance matrix
([conformance.yml](../../.github/workflows/conformance.yml)). Schema changes
will need matching fixtures there.

---

## Part F: Recommended sequence

Ordered by value per unit of effort, with the freeze respected.

**Now, no new spend, roughly two to three weeks**

1. **D1**, security key enrollment. One hardcoded value blocks the entire
   government hard-case story. Highest value line in this document
2. **B.1 AU-3**, add `actor_user_id` and populate it on admin actions
3. **A5**, correct the challenge lifecycle on the authentication path
4. **B.4**, add Dependabot, `npm audit`, CodeQL and SBOM to CI. Cheap, checkable
5. **D4** and **B.2**, move session lifetimes into `system_config` and set a
   real idle timeout distinct from absolute expiry

**Next, still no new spend, roughly two weeks** 6. **A1, A4, A7**, AAGUID column, explicit algorithms including RS1, consistent
user verification policy 7. **A6**, move challenges off the user row 8. **D3**, identity-proofing fields on recovery 9. **B.1 AU-5**, decide and document the audit failure posture, and break the
silent coupling to lockout counting

**Then, the FIDO push** 10. **A2, A3**, MDS and attestation verification. Unlocks **D2**, synced passkey
policy, as a by-product 11. **A8**, the conformance interface behind a flag 12. **A9**, register for the conformance tools and run them. Only start the
90-day interop clock once 1 through 11 are done

**In parallel, business track, not engineering** 13. Buy GovRAMP membership plus the Single Security Snapshot, roughly $1,500.
Assemble the 40-control artifacts from `security-posture.md` and
`production-operations.md` **before** the intake meeting 14. Remediate what the Snapshot actually finds, which supersedes Part B

**Deliberately not now**

- FIPS-validated cryptography. Expensive, and only needed if CJIS is pursued
- Audit log hash chaining. Do the cheaper AU work first and see what scores
- SOC 2. The operating plan is right that it does not fit the budget

---

## Part G: Open questions this analysis cannot answer

1. **Attestation posture.** Requiring attestation gives agencies authenticator
   control and is the basis for D2, but it breaks enrollment for authenticators
   absent from MDS and adds a support burden. Per-agency configurable, and if so
   what is the default?
2. **Audit failure posture.** Fail closed (refuse to authenticate when the audit
   write fails) or fail open with alerting? Fail closed is the defensible
   answer for government and it is an availability risk. This is a positioning
   decision, not an engineering one.
3. **CJIS.** Runbook open decision 2, and the answer this analysis suggests is
   "not today." Confirm before the first Phase 0 call.
4. **Audit retention default.** Runbook open decision 8. Needs a Maryland
   records retention schedule read before a number can be picked.
5. **Data residency.** Runbook open decision 1. Constrains deployment topology
   and belongs in [configuration.md](../configuration.md) once settled.

---

## Sources

- FIDO Functional Certification for servers: https://fidoalliance.org/certification/functional-certification/functional-certification-servers/
- FIDO Server Requirements v2.3 (WebAuthn L3, CTAP 2.3): https://fidoalliance.org/specs/fidoserver/fido-server-v2.3-rd-20260226.html
- SimpleWebAuthn FIDO conformance guidance: https://simplewebauthn.dev/docs/advanced/fido-conformance
- GovRAMP Security Snapshot: https://govramp.org/security-snapshot
- GovRAMP pricing: https://govramp.org/pricing-overview
- Maryland Local Cyber Assessment Tool: https://doit.maryland.gov/About-DoIT/Offices/Office-of-Security-Management/Cybersecurity-Local-Government-Resources/Pages/maryland-local-cyber-assessment-tool.aspx
- Maryland State Minimum Cybersecurity Standards: https://doit.maryland.gov/policies/ci/Pages/state-minimum-cybersecurity-standards.aspx
- NIST SP 800-53 Rev. 5: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- NIST SP 800-63B, authenticator assurance levels: https://pages.nist.gov/800-63-3/sp800-63b.html
