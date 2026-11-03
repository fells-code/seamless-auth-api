---
'seamless-auth-api': minor
---

External delivery now requires the service token in `x-seamless-service-token` to carry subject `seamless-auth-external-delivery` (#556). Any other valid service token, such as an adapter's proxy token, no longer unlocks codes, links or account notices in the response; the API sends them through its own transport instead. The Node, Go, Python and Rust adapters already sign their delivery requests with that subject, so adopters on current adapters need no change. A caller that hand-mints its own service token for external delivery must set `sub` to `seamless-auth-external-delivery`.
