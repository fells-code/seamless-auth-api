---
'seamless-auth-api': minor
---

OAuth sign-in now supports cutting an organization over from a legacy identity provider.

- OAuth providers gain `promptPasskeyEnrollment` (default `false`). With it set, a successful `POST /oauth/:providerId/callback` carries `nextStep: 'enroll_passkey'` when the user has no passkey yet. The session in the response is a full access session, so the client can send the user straight into passkey enrollment. Absent means there is nothing further to do.
- `PUT /admin/organizations/:organizationId/oauth-providers/:providerId/retirement` retires a provider for one organization, and `DELETE` on the same path restores it for a rollback. Each change is recorded as an `admin_oauth_provider_retired` or `admin_oauth_provider_restored` auth event. A member of any organization that retired the provider is refused at the callback with `403` and code `oauth_provider_retired`, before any account is claimed or linked. Retiring a provider also revokes every live session of every member of the organization, whichever method started it, so the cutover takes effect immediately; the count is recorded on the auth event. Retiring a provider that is already retired revokes nothing.
- Organizations gain `retiredOAuthProviders` in every organization response.

Contract change: clients that switch exhaustively over OAuth error codes need the new `oauth_provider_retired` code. Requires a database migration and `@seamless-auth/types` 0.25.0.
