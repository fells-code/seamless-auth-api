---
'seamless-auth-api': major
---

Require identity proofing on admin-assisted device replacement.

**Breaking.** `POST /admin/users/:userId/recovery/device-replacement` now
requires a `proofing` object and answers 400 without one:

```json
{
  "proofing": {
    "method": "in_person",
    "evidenceRef": "TICKET-1042"
  }
}
```

`method` is `in_person` or `remote_exception`. A remote exception is refused
unless it names an `approver`, so taking the weaker path is deliberate and
attributable. `evidenceRef` is a pointer such as a ticket number, not the
evidence itself, because it is written to the audit trail where identifiers are
redacted.

This endpoint revokes every session, removes every passkey and disables TOTP. It
previously recorded nothing about how the operator established who they were
talking to, which made a recovery impossible to review afterwards.

The audit event now carries the proofing record and the acting administrator.
The acting admin currently rides in event metadata; it moves to a first-class
column when `auth_events` gains one.

Callers sending an empty body and relying on the clearing defaults must now send
proofing. Those defaults are unchanged. Requires `@seamless-auth/types` 0.9.0.
