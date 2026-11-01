---
'seamless-auth-api': minor
---

The API now owns which sessions a provider sign-in was made on. The provider service binds a session to a client with `POST /oidc/sessions/:id/bind`, presenting the user's own access token for that session, and the API answers account and auth context lookups, signs provider tokens, and accepts a session revoke only for bound sessions. Account notices need the same binding. Device-flow tokens no longer carry `amr` or `auth_time`, as they already did not carry `acr`.

This raises the provider service contract to version 3, so `seamless-auth-oidc-provider` must be upgraded with the API. Sessions signed in to provider clients before the upgrade need to sign in again to get new provider tokens.
