---
'seamless-auth-api': minor
---

Let a deployment choose which authenticators it will enrol.

Adds the `authenticator_policy` system config key, settable from
`AUTHENTICATOR_POLICY` as JSON:

```json
{ "attachment": "any" }
```

`attachment` accepts `any`, `platform` or `cross-platform`. `any`, the default,
offers both built-in authenticators and roaming security keys at registration,
which is what an agency issuing hardware keys needs. Naming one narrows the
browser picker for every registration on the instance.

The `?attachment=` parameter on `GET /webauthn/register/start` still works, and
is now bounded by the policy: a request asking for a kind a pinned policy
excludes is refused with `400 { "error": "attachment_not_allowed" }` rather than
silently overriding it. A request that agrees with the policy is fine.

Existing deployments are unaffected. The key defaults to `{ "attachment": "any" }`,
which is the behaviour they already had.

Requires `@seamless-auth/types` 0.7.0, which carries the shared schema.
