---
'seamless-auth-api': minor
---

Refuse synced passkeys by default, and let a deployment restrict authenticator models.

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
