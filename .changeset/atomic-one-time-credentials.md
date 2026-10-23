---
'seamless-auth-api': patch
---

Consume one-time credentials atomically. Email and phone OTPs are now cleared with an update conditional on the issuance that was compared, and a TOTP code is only accepted while the stored counter is still older than it, so concurrent submissions of one valid code yield exactly one success. TOTP enrollment enables the pending credential the same way. The losing request gets the same response and audit event as an invalid code.
