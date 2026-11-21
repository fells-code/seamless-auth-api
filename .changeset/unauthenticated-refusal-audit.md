---
'seamless-auth-api': minor
---

Refusals anyone can produce for free no longer write audit events (#596). A request from a disallowed origin (`403`), a request to an unknown route (`404`), and `POST /refresh` with no token or one that matches no session (`401`) used to each write a hash-chained `request_suspicious` or `refresh_token_failed` row, taking the chain head lock. They are now counted in process, and each instance logs a one-line summary at most once a minute. Responses are unchanged. Expect far fewer `request_suspicious` rows in the trail and the security anomaly view. A refresh token that matches a revoked session is still recorded, now against that session and its user. The stored audit user agent is capped at 512 characters and a refused bearer's recorded route at 256.
