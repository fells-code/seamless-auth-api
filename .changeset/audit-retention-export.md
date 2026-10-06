---
'seamless-auth-api': minor
---

Add audit event retention and a bulk export.

- `AUDIT_RETENTION_DAYS` expires audit events older than the period. Expired events are first written to `AUDIT_ARCHIVE_DIR` as NDJSON files, each with a `.sha256` file beside it, and only then deleted. Without an archive directory nothing is deleted. Retention removes only a contiguous run from the start of the hash chain, and never the newest event, so what remains still verifies. `AUDIT_RETENTION_DATABASE_URL` lets the job run as a separate role that holds DELETE. The job runs daily, and each run logs the chain head as an external anchor.
- `GET /admin/auth-events/export?from=&to=` (admin, fresh step-up) streams every event in a period as one `application/x-ndjson` download. Each line carries the exact hashed payload, and a trailing manifest gives the count, the `seq` range, the anchor hash and the last hash, so the file can be verified without the database. Exports are themselves recorded in the audit trail.
