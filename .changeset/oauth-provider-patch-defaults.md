---
'seamless-auth-api': patch
---

Fix `PATCH /system-config/oauth-providers/:id` resetting settings the request did not mention. The parsed patch carried every default from `@seamless-auth/types`, so `{ "enabled": false }` also set `allowSignup: true`, `accountLinking: 'email'` and `requireEmailVerified: false`, emptied `scopes` and `redirectUris`, and reverted the claim paths. Fixed by `@seamless-auth/types` 0.25.0 (fells-code/seamless-auth-types#83).
