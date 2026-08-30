---
'seamless-auth-api': minor
---

Answer a schema validation failure with the documented error body instead of a raw
`ZodError`.

**Behaviour change to the error contract.** A request that fails its route's `params`,
`query` or `body` schema was refused with `res.status(400).json(error)`, passing the
`ZodError` straight to the serializer. That produced
`{ "name": "ZodError", "message": "<the issues, JSON encoded into a string>" }`, which
has no `error` key at all. Every route declares `400: ErrorSchema`, where `error` is
required, so the response violated the contract the route published for itself, and a
client had nothing stable to branch on.

Nothing caught it. The response schema check is installed by the handler wrapper, and
validation fails before that wrapper runs, so the mismatch was never even logged.

For a consumer the practical effect was worse than a missing code. The React SDK reads
`error` and falls back to `message`, so with no `error` present, `registerPasskey()`
surfaced the entire encoded issue list as `error.message`, ready to be rendered to a
user by an app doing the documented thing with an unrecognised failure.

Validation failures now answer with:

```json
{
  "error": "invalid_request",
  "message": "Request failed schema validation.",
  "details": { "issues": [{ "path": ["attachment"], "code": "invalid_value", "message": "..." }] }
}
```

`error` carries the stable code. `details` names the rejected fields, following the same
reasoning as `AdminValidationErrorSchema`, which exists because a plain error schema
would strip that list before it reached the caller. Issues are mapped field by field
rather than passed through, so a refusal does not echo the submitted value back.

`defineRoute` now declares `ValidationErrorSchema` as the `400` for any route that
validates a request, so `openapi.json` documents the response that validation actually
returns. A route that already declares a richer `400` keeps it. `error` stays required
everywhere, so a consumer reading only that field is unaffected, and `details` is
additive.

A throw that is not a `ZodError` is passed to the error handler rather than being
reported as a bad request, since it means a server fault rather than a malformed
request.
