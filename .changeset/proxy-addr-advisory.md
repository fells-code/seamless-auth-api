---
'seamless-auth-api': patch
---

Update `proxy-addr` to 2.0.8 for GHSA-jqcg-44mw-7w3h (critical), where a client could spoof its IP through an IPv4-mapped IPv6 address when a trusted proxy subnet is configured. It affects deployments that set `TRUST_PROXY`, where the client IP feeds rate limiting, lockout and the audit log.
