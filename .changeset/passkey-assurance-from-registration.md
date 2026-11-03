---
'seamless-auth-api': minor
---

Passkey hardware assurance now comes from the registered credential rather than the assertion (#552). Sign-in and step-up refuse an assertion whose backup eligibility flag differs from the one stored at registration (`401`, audited as `webauthn_login_failed` or `step_up_failed` with reason `Backup eligibility differs from registration`). A passkey counts as device-bound, and earns `acr=phrh` and `amr=hwk`, only when it was registered device-bound with attestation verified against the FIDO Metadata Service. Deployments that use the default `none` attestation, and credentials registered before attestation was recorded, now get `phr` and `swk` instead of `phrh` and `hwk`.
