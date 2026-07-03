---
'seamless-auth-api': patch
---

Rate limit the `POST /registration/register` endpoint.

Registration now applies the same per-IP and per-identity limiters already used by
the OTP and phone-registration routes. This closes an unthrottled path that allowed
registration/OTP spam and account enumeration against the endpoint.
