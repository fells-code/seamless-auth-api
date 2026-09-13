---
'seamless-auth-api': minor
---

Read the per-flow rate limits from system config, and document what a native client needs.

The OTP, magic link and OAuth limiters carried their values as constants: 10 OTP sends and 20
magic links per IP per 15 minutes, 5 per address, 30 OAuth starts per IP and 10 per provider.
Those suit a web audience and refuse a mobile one, because carriers put thousands of
subscribers behind one IPv4 address. The six limiters now read `flow_rate_limits` from system
config (`FLOW_RATE_LIMITS` from the environment on first boot), an object whose defaults are
exactly those constants, so an instance that sets nothing behaves as it did. A changed limit
applies on the next request; a changed `windowSeconds` builds a fresh limiter for that window.
`perIdentity` values guard the address and rarely need changing; `perIp` values are what a
deployment serving a native app raises.

`@seamless-auth/types` moves to 0.22.0, which adds the key, and `openapi.json` and the generated
types pick it up on the system config routes.

Docs gain a "Native and mobile clients" section in `api-contract.md` (RP ID and origins for iOS
and Android, magic link and OAuth destinations, the tenant-wide session lifetime, refresh reuse
detection, authenticator policy), a "Flow rate limits" section in `configuration.md`, and the
client SDK packages in `ecosystem.md`.
