---
'seamless-auth-api': patch
---

Self-service account recovery fails closed when the owner cannot be told. `POST /recovery/verify` now voids the request and answers `503` with `recovery_notice_failed` unless the opening notice reached at least one verified address, and it cancels the account's other open requests only after that notice is sent. Before, a request opened even when every notice failed or was skipped for external delivery, so the delay ran without the owner ever getting a cancel link.
