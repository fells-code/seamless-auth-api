---
'seamless-auth-api': patch
---

Owner notices that a delivery-owning adapter does not advertise are now sent directly instead of dropped (#557). Under external delivery with a service token, a notice whose kind is missing from `x-seamless-auth-delivery-kinds` (for example the SMS notice on `/recovery/verify` when the adapter lists only `account_notice_email`) goes out through the API's own email or SMS transport when one is configured, and is recorded as `sent` or `failed` rather than `not_sent_external_delivery`. The same applies to the recovery completed and recovery code used notices and to `POST /applications/account-notices`. A recovery that previously answered `503 recovery_notice_failed` for an adapter listing no notice kinds now proceeds when the API can notify the owner itself. Admin identity-change notices are unchanged.
