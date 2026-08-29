---
'seamless-auth-api': minor
---

Advertise every credential algorithm the FIDO specification requires.

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
