---
'seamless-auth-api': patch
---

A pre-auth token re-minted within an attempt, such as by an OTP resend, now expires when the attempt's first token did, five minutes after `/login` or `/registration/register`. Before, each resend opened a new five-minute window. A user who resends a code late in the window has less time to enter it, and starts again from `/login` once it runs out. Completing an account recovery after its delay always takes a new attempt that proves the channel again.
