---
'seamless-auth-api': minor
---

Return `returnTo` from the OAuth callback, and refuse a scheme that cannot be a link
destination.

`/oauth/:providerId/start` has accepted a `returnTo` since OAuth landed. This service
validated it against the configured origins and signed it into the state, and nothing ever
gave it back, so a client that asked to be returned somewhere had no way to learn where and
the validation changed nothing observable. `/oauth/:providerId/callback` now includes it in
the success body.

The value comes out of the signed state rather than the callback request, so it is the one
accepted at `/start` and not one introduced at the end of the round trip. It is absent when
the caller asked for nothing.

`@seamless-auth/types` moves to 0.20.0, which carries the response field and moves both
`returnTo` fields from `z.url()` to `RedirectTargetSchema`. `z.url()` accepts
`javascript:alert(1)` and `data:text/html,...`, and a client navigates to whatever comes back
out of this flow, so it is the same sink a magic link destination is. `/start` now refuses
those schemes outright. Nothing was exposed before this: `allowedReturnTo` compares origins
and such a URL has none that matches, so it was already dropped. The refusal is now stated
once in the schema instead of depending on a downstream check to fall the right way.

`issueSessionAndRespond` takes an optional `extraFields` so a flow can add to the session
response without session issuance knowing which flow reached it. Each route still validates
its own response against its declared schema.

`openapi.json` and `src/generated/api.ts` are regenerated. Additive: a client that ignores
the new field is unaffected.
