---
'seamless-auth-api': patch
---

OTP and magic link limits and links are scoped to the sign-in attempt, so a stranger who knows an address can no longer use up or void the owner's codes and links (#468).

- The OTP and magic link identity limiters key `flow_rate_limits.*.perIdentity` on the identifier plus the ephemeral token's attempt (`jti`), or the requester's IP when there is none. Another attempt for the same address keeps its own allowance.
- Every attempt for one identifier together is capped at four times `perIdentity` (20 per window by default), so minting fresh attempts still cannot message an address without bound.
- `POST /magic-link` expires only earlier links from the same attempt instead of every link for the account.
- `FLOW_RATE_LIMITS` / `flow_rate_limits` keep their shape and meaning. No new config key.
