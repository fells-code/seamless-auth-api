---
'seamless-auth-api': minor
---

Give WebAuthn challenges their own store, with an expiry and one-time use.

Challenges lived in a single `users.challenge` column shared by registration,
login and step-up. Three consequences, all fixed here:

- **Flows clobbered each other.** Starting a login invalidated a registration
  already in flight for the same user, and a second tab invalidated the first.
  Challenges are now keyed by user and flow, so registration, login and step-up
  can be outstanding at once.
- **Nothing expired.** The column had no lifetime, so a challenge stayed valid
  until some later flow happened to overwrite it. The `timeout` in the credential
  options is only a hint to the browser and was never enforced. Challenges now
  expire server side after five minutes, comfortably longer than that hint so no
  legitimate ceremony is cut short.
- **A challenge could outlive its ceremony.** It is now spent when verification
  reads it, before anything else can fail, so an attempt that fails leaves
  nothing redeemable behind.

A magic link completing also spends any half-finished WebAuthn ceremony for that
user, preserving what the old defensive clear did.

`users.challenge` and `users.challengeContext` are no longer read or written.
They are left in place so this release can be rolled back, and should be dropped
in a follow-up once it has run in production.
