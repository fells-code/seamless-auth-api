---
'seamless-auth-api': minor
---

Stop recording a WebAuthn registration success before anything is registered.

`GET /webauthn/register/start` logged `webauthn_registration_success` at the end
of options generation, before the client had done anything and before any
credential existed. Every abandoned or failed registration produced a success
event, so registration counts, dashboards and anomaly detection were all
measuring the wrong thing. Because outcome is derived from the `_success`
suffix, those events were also counted as successful WebAuthn activity in the
metrics.

Issuing options now logs `webauthn_registration_challenge`, matching
`login_challenge` on the login path. It categorises as `webauthn` with outcome
`other`, so it no longer inflates the success figures. The real
`registration_success` stays where it belongs, on verified registration in
`/webauthn/register/finish`.

`webauthn_registration_success` is removed from the declared event types, since
it is now emitted nowhere and this repository deliberately prunes types nobody
writes so consumers do not filter and alert on names that never arrive. Stored
events keep that type and remain readable and filterable by exact type; they are
no longer swept into the `webauthn` category filter.
