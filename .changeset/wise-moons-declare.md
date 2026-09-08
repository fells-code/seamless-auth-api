---
'seamless-auth-api': patch
---

Every route now documents the `429` and `500` it can actually answer with.

`openapi.json` contained zero `429` responses while seventeen routes carry a per-flow
limiter and every route sits behind the global one, so a rate limited response was
reachable everywhere and documented nowhere. The same was true of the `500` from the
top-level error handler on the routes that did not declare one. `src/generated/api.ts` is
emitted from the spec and committed, so a consumer reading it, or generating their own
client, got a response union that could not see either case.

`defineRoute` now adds both to every route it registers, the way it already adds the `400`
validation response, and a route that declares one of them itself keeps its own. Both are
the canonical `{ error }` body, which is what the limiters and the error handler actually
send.

Documentation only. Nothing about how a request is handled or answered changes: these
responses feed the OpenAPI registry, not the runtime response validation, which still
reads only what a route declares.
