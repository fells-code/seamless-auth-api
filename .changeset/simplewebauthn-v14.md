---
'seamless-auth-api': patch
---

Update `@simplewebauthn/server` to 14.0.3 for GHSA-2g3p-m8c9-hhwh and GHSA-j3h4-m3m2-7p7j. During registration, an attestation certificate chain could make the server fetch a CRL from an attacker-chosen URL and cache it unverified in the process-wide revocation cache, influencing revocation checks for later registrations. 13.x carries the same code and has no patched release. The advertised public key algorithms are unchanged, since the API sets them explicitly, so the new ML-DSA (post-quantum) default does not apply.
