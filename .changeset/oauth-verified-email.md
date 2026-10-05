---
'seamless-auth-api': minor
---

OAuth sign-in now links to an existing account, or creates a new one, only when the provider asserts the email is verified (`email_verified: true`), whatever `requireEmailVerified` is set to. A profile without that assertion is refused with `400` and code `oauth_email_not_verified`, the same response an explicitly unverified email already gets. Identities that are already linked keep signing in as before.

GitHub's `/user` carries no verification status, so a GitHub provider (recognised by a `userInfoUrl` of `https://api.github.com/user` or a GitHub Enterprise Server `/api/v3/user`) now reads `/user/emails` and uses the address GitHub lists as verified: the profile email when it is verified, otherwise the primary verified one. This needs the `user:email` scope, which the CLI preset already requests.

This is a breaking change for providers whose profile does not include `email_verified`, such as Microsoft Graph's `oidc/userinfo`: new users and first-time links through them are refused until the provider supplies a verified email. An existing account that had not yet verified its email (for example one created by an admin) is marked verified when a verified provider email links to it.

When an account's email is verified for the first time, through email OTP or a verified OAuth email, a phone that was verified before then is kept only if the same registration attempt verified it. Phone-first sign up is unaffected; a phone verified under a different attempt is removed. Adds the `users.phone_verified_attempt_id` column (migration `20261005150000`).
