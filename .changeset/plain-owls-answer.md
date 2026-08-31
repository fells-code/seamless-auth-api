---
'seamless-auth-api': minor
---

Answer a rate-limited request with the JSON error shape.

Every other `4xx` and `5xx` on this API is `{ "error": "..." }`. A `429` was the one
exception: express-rate-limit sends a string `message` through `res.send`, which lands
as `text/html`, so a client parsing error bodies as JSON got a parse failure instead of
an error.

Three limiters set that string explicitly. The other six set no message at all and
inherited the library's own string default, so they were plain text too. All nine sites,
including the JWKS limiter, now send an object and answer:

```json
{ "error": "Too many requests, please try again later" }
```

**Behaviour change:** the `429` body and its content type change. Two consumers were
already coping with the text form rather than depending on it. `@seamless-auth/core`
carries a `makeJsonTolerant` shim in `authFetch` that names this case in its comment,
and `seamless-auth-react` was crashed by it once already. The admin dashboard maps `429`
to fixed wording and never surfaces upstream text, so it is unaffected.

The unreachable `message` on the slow-down is removed rather than converted.
express-slow-down replaces the handler with one that only delays and calls `next`, so it
never answers a request and that option could never be read.
