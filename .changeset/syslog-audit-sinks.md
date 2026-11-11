---
'seamless-auth-api': patch
---

Syslog audit sinks are available (#586). Creating or updating a syslog sink no longer returns a 400. Records go over RFC 5424 on TLS with octet counting, and carry `seq` and `hash` in the structured data element `seamless@67592`, under the Fells Code IANA Private Enterprise Number 67592. Key collector parsing rules on that SD-ID.
