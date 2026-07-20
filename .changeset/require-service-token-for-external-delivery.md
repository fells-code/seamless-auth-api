---
'seamless-auth-api': minor
---

Require a validated internal service token for external delivery in all environments. `canReturnExternalDelivery` no longer treats a non-production `NODE_ENV` as sufficient, so the `x-seamless-auth-delivery-mode: external` header must now be accompanied by an `x-seamless-service-token` that passes issuer, audience, and subject validation. `canReturnSensitiveDevelopmentDetails` is gated the same way. Local development that cannot present a service token can set `ALLOW_UNCREDENTIALED_DELIVERY_SECRETS=true`, an explicit opt-in that is ignored when `NODE_ENV=production`.
