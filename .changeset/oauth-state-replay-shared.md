---
'seamless-auth-api': patch
---

A replayed inbound OAuth `state` is now refused by every instance, not only the one that first consumed it. The replay record moved from process memory into the `oidc_payloads` table (model `OAuthStateReplay`), written only if absent in one statement and kept until the state expires ten minutes after it was issued. OAuth callbacks no longer need sticky routing behind a load balancer. If the database is unreachable the callback fails rather than skipping the check.
