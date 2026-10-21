---
'seamless-auth-api': patch
---

Passkey sign-in challenges belong to the sign-in attempt that asked for them (GHSA-v9q2-hcqj-ggqr).

- `POST /webauthn/login/start` stores its challenge against the pre-auth token's attempt (`jti`) and replaces only that attempt's earlier challenge. Starting another attempt for the same account, which only needs its email address, no longer invalidates the challenge the owner is answering.
- `POST /webauthn/login/finish` checks the assertion against its own attempt's challenge.
- A pre-auth token without a `jti` is refused on login start with `400`.
- Challenges are spent with a conditional update, so two verifications racing for one challenge cannot both use it.
- Migration: `webauthn_challenges` gains `attempt_id`. Passkey sign-ins in progress during the upgrade have to start again.

Registration and step-up challenges are unchanged: both already need an access session.
