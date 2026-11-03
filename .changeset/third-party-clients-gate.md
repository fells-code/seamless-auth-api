---
'seamless-auth-api': minor
---

`third_party_clients_enabled` now gates existing third-party OpenID Provider clients, not only creating and updating them (#555). While it is off, a client that is not first-party is treated like a disabled one: `/oidc/clients/:id` answers `404`, its shared secret does not verify, `/oidc/sign` refuses with `client_inactive`, its notice tokens are refused and back-channel logout skips it. An instance that turned the flag off after registering third-party clients stops serving them on upgrade; turn the flag back on, or mark the applications first-party, to keep them working.
