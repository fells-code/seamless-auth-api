---
'seamless-auth-api': minor
---

Make session lifetimes configurable, and give the idle bound a chance to fire.

Session expiry came from two hardcoded constants, both one day. Because they
were equal, `idleExpiresAt` and `expiresAt` always landed on the same instant,
so the idle bound could never fire before absolute expiry. In practice there was
no idle timeout at all, despite the session model carrying the column and the
lookup queries filtering on it.

Two changes:

- The absolute session lifetime now comes from `refresh_token_ttl`, which
  already existed and was already reported to clients as `refreshTtl`. It was
  not previously applied to the session row, so an instance with
  `REFRESH_TOKEN_TTL=30d` told clients thirty days and expired the session after
  one. Setting it now does what it says.
- The idle bound comes from the new `session_idle_ttl`
  (`SESSION_IDLE_TTL`), default `8h`.

**Behaviour change.** On stock configuration a session that goes unrefreshed
now ends after 8 hours rather than 24. Any client refreshing normally is
unaffected, because rotation resets the bound and access tokens are far shorter
lived; only genuinely idle sessions end sooner. Instances that want the previous
behaviour can set `SESSION_IDLE_TTL=1d`, and deployments with a stricter posture
typically want 15m to 30m.

An instance that previously relied on `REFRESH_TOKEN_TTL` being longer than one
day will see sessions live as long as that value now actually says, which is
longer than before. Check that value if it was set to something large on the
assumption it was inert.

Requires `@seamless-auth/types` 0.8.0.
