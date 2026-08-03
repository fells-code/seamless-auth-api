---
'seamless-auth-api': patch
---

Add `TRUST_PROXY` so the client address can be read from `X-Forwarded-For`.

Express leaves `trust proxy` off by default, so behind a load balancer `req.ip` resolved to the
balancer rather than the caller. Every client shared one bucket in the global rate limiter and the
slow-down middleware, and `express-rate-limit` logged an `ERR_ERL_UNEXPECTED_X_FORWARDED_FOR`
validation error on each request. Set `TRUST_PROXY` to the number of proxies in front of the server
(`1` behind a single load balancer) to restore per-client limiting. It stays unset by default
because a directly reachable server that trusts the header lets a client forge its own address.
