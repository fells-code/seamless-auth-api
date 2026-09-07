---
'seamless-auth-api': minor
---

Default `authenticator_policy.syncedPasskeys` to `allow`.

This reverses the default shipped in 0.8.0. `block` refuses any credential that
is backup eligible, and every iCloud Keychain and Google Password Manager passkey
is one, so a stock instance refused the passkey a normal laptop or phone actually
offers. A fresh `seamless init` came up unable to complete a single registration,
on hardware the operator had no way to change. That is a posture to be chosen,
not inherited.

A deployment that issues its own authenticators still sets `block`, and it now
reads as the deliberate choice it is:

```json
AUTHENTICATOR_POLICY={"syncedPasskeys":"block", ...}
```

**What changes on upgrade.** `bootstrapSystemConfig` only applies a default when
the row is absent, so 0.8.0's seeded `block` would otherwise outlive this release
on every existing install. A migration flips it, and only on rows nobody chose:
`authenticator_policy` with `updatedBy IS NULL`. A deployment that set `block`
through the admin API keeps it, and one that set it through
`AUTHENTICATOR_POLICY` has it re-applied from the environment on the next boot.
If you want the 0.8.0 behaviour, name the field.

Nothing else moves. The judgement is still made on backup eligibility rather than
current backup state, the refusal is still
`403 { "error": "synced_passkey_not_allowed" }`, and existing credentials are
untouched either way.
