---
'seamless-auth-api': major
---

Remove the admin bootstrap invite flow. `POST /internal/bootstrap/admin-invite` is gone, along with
the `bootstrapToken` field on `POST /registration/register`, the `bootstrap_invite_email` external
delivery kind, the `bootstrap_admin_granted` and `bootstrap_admin_check_skipped` auth event types,
and the `SEAMLESS_BOOTSTRAP_ENABLED`, `SEAMLESS_BOOTSTRAP_SECRET`, and `SEAMLESS_AUTH_DEBUG_SECRETS`
environment variables. A migration drops the `bootstrap_invites` table.

The first admin is now granted through `OWNER_EMAIL`: a user who signs up with a configured owner
email receives the admin role on account creation.
