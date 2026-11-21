---
'seamless-auth-api': patch
---

A `system_config` change now takes effect on every instance within about a second, not only on the instance that took the write (#597). Each instance used to cache config for five minutes, so disabling a login method, removing an OAuth provider or turning on `phishing_resistant_only` could stay ineffective on the other replicas for that long. Each instance now compares a hash of the stored rows with its cached copy at most once a second and reloads when they differ. Direct database edits are picked up the same way. If that check cannot reach the database, the config read fails instead of serving a copy it cannot show is current.
