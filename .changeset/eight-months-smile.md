---
'seamless-auth-api': minor
---

Adopt `@seamless-auth/types@0.3.0` as the source for the shared contract. 88 schema definitions
across 30 files become re-exports, removing roughly 900 lines of definitions this repo maintained
in parallel with the SDKs, the dashboard, and the CLI. `roleGrantsAccess`, `hasScopedRole`, and
`ROLE_NAME_PATTERN` now come from the package too, and the local transport widening shim added
alongside the passkey fix is gone since the shared `TransportSchema` carries the full WebAuthn set.

Two response shapes change as a result:

- Organization and membership `createdAt`/`updatedAt` were `z.any()` and are now typed ISO
  date-times and required. They were always sent; they are now documented accurately.
- `magic_link_email` delivery marks `token` optional, and anomaly events mark `type` optional,
  matching the shared schemas. Both are still always present in responses.

Several schemas stay local because the shared versions would lose behavior: the pruned auth event
list and the query filter built on it, the interval-aware metrics window cap, the timeseries
`total`/`categories` fields, the grouped-summary `outcomes`, the OTP and magic-link success
envelope that carries `token` and `delivery`, PRF salt validation, role assignment validation, and
the JWKS and health responses that no other repo consumes. Each is commented with why.
