---
'seamless-auth-api': minor
---

Let OpenID Provider tokens carry roles, permissions and custom claims (seamless-auth-oidc-provider#47).

- `GET /oidc/accounts/:id` now returns the ADR 0004 permission claims (`permissions`, `org_roles`, `org_permissions`, or `permissions_omitted`) and `customClaims`, computed for the session and client the lookup names, with the same shared 1 KiB budget as a first-party token. An omission writes `custom_claims_omitted` with the client id.
- Custom claims for a provider token add the client's `oidc_client` set after the instance and organization role sets and before the session's `pre_token` hook claims.
- `org_id` for a provider token is now the session's active organization, while the user is still a member, instead of the user's oldest membership. This is a behavior change for provider clients that read `org_id`.
- `/oidc/sign` signs these claims only with the values it computes again for that session and client. A different value is refused as `subject_mismatch`, a custom claim name it did not compute or a reserved name as `malformed_signing_input`, and a permission or custom claim set carried in part as `subject_mismatch`. Client credentials tokens still carry none of them.
