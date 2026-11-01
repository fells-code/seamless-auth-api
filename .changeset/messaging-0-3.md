---
'seamless-auth-api': patch
---

Depend on `@seamless-auth/messaging`, `@seamless-auth/messaging-aws` and `@seamless-auth/messaging-twilio` 0.3. Direct email delivery now sends through SES v2. The IAM action is still `ses:SendEmail`, so deployments need no policy change.
