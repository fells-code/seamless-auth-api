---
'seamless-auth-api': patch
---

Derive the default authenticator policy from the schema instead of restating it.

`SYSTEM_CONFIG_DEFAULTS.authenticator_policy` listed each field by hand, so a
field added to `AuthenticatorPolicySchema` upstream stayed absent here until
somebody noticed. That is not hypothetical: it is how the default fell behind
when the schema gained `attestation` and `requireKnownAuthenticator`, and again
when it gained `syncedPasskeys`, `aaguidAllowList` and `aaguidDenyList`.

Parsing the schema with no input yields exactly the same object it produced by
hand, so nothing changes today. What changes is that the next field arrives with
the default the schema gives it rather than silently missing, and a test now
fails if the two ever disagree.
