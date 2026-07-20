---
'seamless-auth-api': patch
---

Bind the `aud` claim on signed user tokens. `signAccessToken`, `signRefreshToken`, and `signEphemeralToken` now call `.setAudience(ISSUER)` in addition to `.setIssuer(ISSUER)`. The Seamless adapter verifies signed auth responses with `aud === audience`, and the deployment contract requires the adopter's `audience` to equal its `authServerUrl`, which is byte-identical to this server's `ISSUER`. Without the claim, jose rejects every token the adapter checks, so login, registration, OAuth, OTP, magic-link, and organization-switch all fail once the adapter's audience binding ships. The claim is additive and ignored by verifiers that do not check it.
