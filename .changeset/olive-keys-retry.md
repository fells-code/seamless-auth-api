---
'seamless-auth-api': patch
---

Turning on attestation at runtime now takes effect immediately rather than up to five
minutes later.

`initializeMetadataService` stamped its retry throttle on entry, before the early return
for a deployment that does not ask for attestation. A instance booting under
`attestation: 'none'` therefore recorded an attempt it never made, and
`ensureMetadataServiceReady` declined to retry until the interval elapsed. An
administrator who patched `authenticator_policy` to `direct` shortly after boot got the
permissive half of the policy in the meantime: a credential that could not be traced to a
manufacturer was still refused, but the metadata lookup that refuses a model the blob does
not list never ran, and `attestationVerified` was recorded false on credentials that would
have verified.

The stamp now sits with the `MetadataService.initialize` call it is meant to throttle. A
path that decided there was nothing to do no longer spends the budget, and neither does a
config read that failed before reaching the network.
