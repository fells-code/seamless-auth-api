---
'seamless-auth-api': minor
---

Allow hardware security keys to be enrolled.

`GET /webauthn/register/start` pinned `authenticatorAttachment` to `platform`, which
hid roaming authenticators from the browser picker entirely, so USB and NFC security
keys could not be registered at all. Only built-in authenticators (Touch ID, Windows
Hello, Android biometrics) were reachable.

Registration now leaves the attachment unset by default, so the browser offers both
kinds. Callers that want to narrow the picker can pass `?attachment=platform` or
`?attachment=cross-platform` on `register/start`; anything else is rejected with a 400.

This changes the default enrolment experience: users who previously saw only the
built-in authenticator will now also be offered a security key. Deployments that
genuinely want the old behaviour should pass `?attachment=platform`.
