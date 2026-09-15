---
'seamless-auth-api': patch
---

A decoy continuation under external delivery no longer hands the SDK a message to send.

When an adopter runs external delivery, the decoy responders for an OTP send and a magic
link request answered with a `delivery` block like a real account's, addressed to the
decoy's synthetic `@example.invalid` email. The SDK mailed it, the domain never resolves,
and the adopter's mail provider retried for hours and then bounced it against the
adopter's sending identity. Every sign-in attempt for an unknown address was a guaranteed
bounce, fourteen hours later, on traffic the adopter does not control (#321).

The responders now omit the block. It is only readable by a caller holding a service
token, so a stranger sees the same answer as before, and the SDK's `deliverAuthMessage`
already sends nothing when the block is absent. `decoyOtpFor` had no other reason to
exist and is removed. `docs/security-posture.md` says why parity at the SDK's edge was
not worth a bounce per probe.
