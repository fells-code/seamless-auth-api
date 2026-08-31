---
'seamless-auth-api': minor
---

Upgrade to Express 5.

The HTTP contract is unchanged: every behaviour Express 5 alters by default is
pinned or restored, so no caller has to adapt. Four things needed real work.

- **Query validation stopped applying.** Express 5 exposes `req.query` as a
  getter with no setter that re-reads the URL on every access, so the assignment
  in `defineRoute` threw and every route with a query schema answered 404. The
  validated query is now installed as an own property, which is what makes the
  schema's coercions survive into the handler.
- **The query parser default changed** from `extended` to `simple`, which would
  have read `a[b]=1` as the literal key `a[b]`. Pinned back to `extended` so an
  upgrade here never silently changes how a caller's query string parses. A move
  to the narrower parser stays available as a deliberate change.
- **A request with no body now arrives as `undefined`** rather than `{}`. Bodies
  are validated as `{}` when absent, so a body-less request still reports its
  missing fields instead of one opaque "expected object, received undefined", and
  `DELETE /admin/users` answers `User not found.` as before rather than throwing.
- **The SPA history fallback route no longer parsed.** path-to-regexp v8 rejects
  a bare `*`, so `/console/*` is now the named `/console/*splat`.

Route params are typed through a new `RouteRequest`, since Express 5 widens
`req.params` to `string | string[]` for the repeatable params this API does not use.
