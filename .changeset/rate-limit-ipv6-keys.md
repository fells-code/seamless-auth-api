---
'seamless-auth-api': patch
---

The magic link, OTP and OAuth flow rate limiters key an IPv6 client on its /56 when they fall back to the client address, as the other limiters already do. Keyed on the full address, a client holding a whole IPv6 range could take a fresh bucket for each request. Requests keyed on an email or phone number are unchanged.
