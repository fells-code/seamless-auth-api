---
'seamless-auth-api': minor
---

Record which authenticator a credential came from.

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
