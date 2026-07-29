---
'seamless-auth-api': minor
---

Prune auth event types that nothing emits, and fix the consumers that searched for them.

15 of the 74 declared types had no emit site anywhere in `src/`. Five of them were actively
queried by the security anomaly detector (`bearer_token_failed`, `jwks_failed`, `otp_failed`,
`recovery_otp_failed`, `user_data_failed`), so those failure categories always returned nothing,
while `verify_otp_failed`, `totp_failed`, `magic_link_failed`, and `logout_failed` were emitted and
never searched for. The admin event filter had the same problem: `otp` expanded to a type nothing
emits and missed every `verify_otp_*` and `mfa_otp_*` event, and `suspicious` named two types that
are never written.

Removed: the `bearer_token_*` and `jwks_*` families, `recovery_otp_*`, `user_data_failed`,
`user_data_success`, `otp_failed`, `mfa_otp_suspicious`, `service_token_suspicious`, and
`webauthn_login_suspicious`.

The failure and suspicious groupings are now derived from `AUTH_EVENT_TYPES` instead of being
hand-copied, so adding an event type files it in the right bucket automatically. A test asserts
every declared type has an emit site, which is what would have caught the removed `bootstrap_admin_*`
entries when that feature went away.

Reading historical rows is unaffected: stored events are returned as `z.string()` and the query
filter accepts any string, so events recorded under a removed name still appear.
