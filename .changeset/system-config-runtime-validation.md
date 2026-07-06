---
'seamless-auth-api': patch
---

Validate `system_config` on the runtime read path.

`getSystemConfig()` now parses stored configuration against `SystemConfigSchema` on load
instead of trusting the database rows with a cast. Invalid configuration fails loudly (the
call throws and the error is logged) rather than flowing malformed values into auth logic.
Also corrects the cache TTL comment (the value is 5 minutes, not 30 seconds).
