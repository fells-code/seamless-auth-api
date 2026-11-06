---
'seamless-auth-api': patch
---

Starting the server no longer rewrites an env-backed `system_config` row, or warns that an admin change is being reverted, when the stored value only orders its keys differently. Postgres JSONB does not keep key order, so object values such as `lockout_policy` and `flow_rate_limits` looked changed on every boot.
