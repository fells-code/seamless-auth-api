---
'seamless-auth-api': patch
---

Keep the package pre-1.0 until cutting 1.0 is a decision.

Two changesets asked for a major bump, which would have released 1.0.0 as a side
effect of landing a breaking change rather than because the code was judged ready
for it. Both are now minor, which under 0.x already signals a break, and both keep
the breaking-change warning in their body where it does the reader some good.

A CI check fails the build on any major changeset, so the next breaking change
cannot quietly reintroduce this. Delete that check in the same change that cuts
1.0.
