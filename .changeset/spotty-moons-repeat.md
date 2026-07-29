---
'seamless-auth-api': patch
---

Stop truncating passkey transports. A cross-device passkey reports `hybrid`, older Chrome reported
`cable`, and security keys can report `smart-card`, but the credential serializer filtered
`transports` down to the pre-hybrid `usb`/`ble`/`nfc`/`internal` set before building the response.
Those credentials reported an empty transport list to every client, including `/users/me` and the
admin user detail view.

Stored data was never affected: the column is unconstrained JSON and registration writes the value
through verbatim, so the correct transports come back as soon as the read path stops dropping them.
No migration or backfill is needed.

`CredentialResponseSchema` carries a local override widening `transports` to the full WebAuthn set,
because `@seamless-auth/types@0.1.3` still declares the narrow one. The override and
`src/lib/authenticatorTransports.ts` can both be deleted once the widened types release is adopted.
