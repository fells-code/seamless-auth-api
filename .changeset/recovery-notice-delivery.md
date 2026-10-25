---
'seamless-auth-api': patch
---

Account recovery works with adapter-owned delivery, and a signed-in owner can cancel it.

- `POST /recovery/verify` returns the "recovery opened" notices as `deliveries` (`account_notice_email` / `account_notice_sms`, with the `cancelUrl`) to a credentialed caller that owns delivery and lists those kinds in the new `x-seamless-auth-delivery-kinds` header. A caller that owns delivery but does not list them still gets `503 recovery_notice_failed`, since an older adapter would drop a kind it does not know. The adapter manifest marks the route `notices: true`.
- The recovery code from `POST /recovery/start` carries `purpose: "account_recovery"` under external delivery.
- `GET /recovery/requests` and `DELETE /recovery/requests/:id` (access session) list and cancel the account's open recovery requests without the token from the notice.
- Updates `@seamless-auth/types` to 0.31.0.
