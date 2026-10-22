---
'seamless-auth-api': patch
---

Changing a user's email or phone through `PATCH /admin/users/{userId}` now signs the user out and tells them (#475).

- Every active session for the user is revoked, in the same transaction as the change. Access tokens already issued stay valid until they expire.
- A notice goes to the previous address and to the new one, by email for an email change and by SMS for a phone change, through the configured direct transports. A failed notice does not fail the request.
- The `internal_user_updated_by_owner` audit event records `identityChanges` (SHA-256 digests of the previous and new values), `revokedSessions` and the outcome of each notice.
- With `x-seamless-auth-delivery-mode: external` no notice is sent, because the delivery payload has no kind for account notices yet. Each is recorded as `not_sent_external_delivery`.

The response shape is unchanged.
