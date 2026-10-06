---
'seamless-auth-api': minor
---

Make `auth_events` append-only and tamper-evident. A new migration adds a hash chain (`seq`, `prev_hash`, `hash`, assigned by an insert trigger and serialized through a one-row `auth_event_chain_head` table), and triggers that refuse UPDATE, TRUNCATE, and any DELETE outside the retention job. `GET /admin/auth-events/integrity` recomputes the chain and reports the first edited, missing or reordered row, along with the current head to record outside the database.

The migration drops the `auth_events.user_id` foreign key. Its `ON DELETE SET NULL` rewrote audit rows whenever a user was deleted. Audit rows now keep the id of the user they were about after that user is deleted. Existing rows are chained in the order they were written when the migration runs, which takes a pass over the whole table.
