---
'seamless-auth-api': minor
---

`POST /oidc/sign` now needs `grantType` on every user token (`@seamless-auth/types` 0.34.0-next.4, edge contract version 2) and checks it against the client. A device-code token is signed only for a first-party client with `deviceFlowEnabled`, and never with `acr`, so a device approval cannot lend the approving session's phishing-resistant assurance to whoever holds the device (ADR 0001, D10). An authorization-code token needs the client to have that grant. Client metadata for the provider service lists the device grant only for a first-party client with the flag on, whatever the stored grant list says.
