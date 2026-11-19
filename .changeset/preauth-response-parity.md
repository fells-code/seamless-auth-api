---
'seamless-auth-api': minor
---

Pre-auth endpoints answer the same way whether or not an account exists.

- `POST /registration/register` for an address that belongs to a verified account answers as a new, unclaimed sign-up: a different `sub`, a pre-auth token over it, no code sent to the owner and no `delivery` block. A user who already has an account signs in instead. An unverified account is answered as before.
- Every route that accepts a pre-auth token, and `/registration/register`, is held to `LOGIN_RESPONSE_FLOOR_MS` (default `250`), success or failure. A deployment whose mail or SMS provider is slower than that should raise it.
- `GET /otp/generate-phone-otp` for an account with no phone answers `200` and sends nothing, instead of `400 Invalid data`, as it already did for a verified account.
- `GET /magic-link/check` from a device that does not match the request answers `204` instead of `403`.
- `POST /webauthn/login/finish` answers `401 Authentication failed.` instead of `500` when the assertion fails verification, and refuses PRF output with `400 prf_output_not_allowed` for every subject.
- The four OTP verify endpoints answer every failure with `401 { "error": "Not allowed" }`.
