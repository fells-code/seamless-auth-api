---
'seamless-auth-api': minor
---

The audit chain head is protected and can be signed (#595).

- A new migration adds a trigger to `auth_event_chain_head` that refuses INSERT, DELETE and TRUNCATE, and any change to `seq` or `last_hash` outside the `auth_events` insert trigger, which now runs as SECURITY DEFINER. A role that deletes the newest audit events can no longer move the head back to hide it, so `GET /admin/auth-events/integrity` reports the loss as `head_mismatch`.
- New optional `AUDIT_CHAIN_KEY`. When set, every audit insert signs the new head with an HMAC under it, and the integrity check fails a head whose signature is missing (`head_unsigned`, a new `reason`) or does not verify (`head_mismatch`). Set it on every instance. The migration signs the head when the key is set while it runs. Otherwise sign it once with `node dist/scripts/sealAuditHead.js`, and again after rotating the key. Production warns at boot while it is unset.
- The integrity report gains `headSigned`.
- `docs/security-posture.md` now recommends revoking writes on `auth_event_chain_head` as well, and notes that the retention setting is open to any session, so the DELETE privilege is the control.
