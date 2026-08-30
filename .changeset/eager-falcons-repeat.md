---
'seamless-auth-api': minor
---

Support attestation, and validate it against the FIDO Metadata Service.

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
