---
'seamless-auth-api': minor
---

Refuse a request from an origin that is not allowlisted, instead of running it.

The CORS origin callback rejected an unknown origin by returning `false` rather
than an error, so the handler that exists to turn a rejection into a `403` keyed
off an error message that was never raised and could not fire. What actually
happened was that `cors` omitted the `Access-Control-Allow-Origin` header and
called `next()`: the route ran, and only the browser discarded the response. For
an authentication server that is the wrong way round, since a disallowed origin
should not be able to make the server act.

An unlisted origin is now refused with `403 { "message": "CORS policy does not
allow this origin." }` before the route runs, preflights included.

Two kinds of request are deliberately still allowed. One carrying no `Origin`
header at all, which is every server adapter, backend and command-line caller.
And a same-origin request: a browser sends `Origin` on every state-changing
request, same-origin ones included, so without this the admin console at
`/console` would need its own host in `APP_ORIGINS` despite being served by this
very process. That comparison is on host rather than scheme, so it does not
silently depend on `TRUST_PROXY` being set behind a TLS-terminating proxy.

The refusal no longer sets an `Access-Control-Allow-Origin` header naming the
first allowed origin, which disclosed part of the allowlist to a caller that was
not on it and helped the browser not at all. It is recorded as one
`request_suspicious` event carrying the real client address and user agent, with
the rejected origin in an `origin` metadata field rather than in `ipAddress`.
