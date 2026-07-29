---
'seamless-auth-api': minor
---

Standardize the error response shape. Every `4xx` and `5xx` response now carries a required
`error` string, with `message` reserved for optional extra detail, so a consumer reads one field
to learn why a call failed.

25 handlers across the WebAuthn, user, internal metrics, dashboard, and security endpoints
returned `{ message }` with no `error`. They now set `error`. Eight error responses on the
`/internal/*` routes were declared with `MessageSchema`, which has no `error` field and would have
stripped it; they now use `ErrorSchema`.

`InternalErrorSchema` was a byte-identical duplicate of `ErrorSchema` and is now a deprecated alias
of it. Nothing changes on the wire for the 53 routes that reference it.

Success responses are untouched: `{ "message": "Success" }` on a `200` is a success payload, not an
error body.

A new conformance test walks every registered route and fails if a failure response declares a
schema without a required `error` string, so a new route cannot reintroduce the split.
