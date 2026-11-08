---
'seamless-auth-api': minor
---

Stream audit events to a SIEM (ADR 0005, #420).

- Admin API under `/admin/audit-sinks`: create, update, disable and delete sinks, and send a test record. Every write takes step-up and is audited as `admin_audit_sink_created`, `admin_audit_sink_updated` or `admin_audit_sink_deleted`.
- OTLP/HTTP with JSON encoding to `<endpoint>/v1/logs`. Syslog (RFC 5424 over TLS, octet counted) arrives in 0.23.1: creating or updating a syslog sink is refused with a 400 until its structured data ID carries the Fells Code IANA enterprise number (#586).
- Every record carries the event's `seamless-auth-events/1` export line, so the hash chain verifies downstream as an export does.
- Each sink has its own cursor and retries until its collector takes the events, backing off to one minute. There is no dead letter: a sink reports how far behind the chain head it is.
- Credentials are never stored. A sink names env vars ending `_AUDIT_SINK_SECRET`, read at send time.
- Audit retention no longer deletes events a sink has yet to deliver.
