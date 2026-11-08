---
'seamless-auth-api': minor
---

Add signed, retried webhooks (ADR 0005, #418).

- Admin API under `/admin/webhooks` and `/admin/webhook-deliveries`: create, update, disable and delete endpoints, rotate the signing secret (the old one signs beside the new one for 24 hours), send a test event, list deliveries with a dead letter filter, and redeliver. Every write takes step-up and is audited.
- Payloads are signed with the Standard Webhooks scheme (`webhook-id`, `webhook-timestamp`, `webhook-signature`), so any Standard Webhooks verifier checks them.
- Events are built from committed audit rows, retried eight times over just under 42 hours, then dead-lettered. An endpoint that answers 410, or fails every delivery for three days, is disabled. Deliveries for a disabled endpoint are held, and turning it back on sends what it missed, up to the 30 days deliveries are kept.
- Every callout to an adopter URL refuses link-local, multicast and the API's own host, never follows redirects, and in production refuses private addresses unless the host is listed in the new `CALLOUT_PRIVATE_HOSTS`.
- New env var `CALLOUT_SECRET_ENCRYPTION_KEY` encrypts stored signing secrets. Production requires it once a webhook exists.
- New audit event `session_created`, written once per completed sign-in. Deleting a passkey is now audited as `credentials_deleted`, and passkey registration names the credential.
