---
'seamless-auth-api': minor
---

Adds the API side of the OpenID Provider service (ADR 0001): service-token routes under `/oidc/*` for fells-code/seamless-auth-oidc-provider, and the tables they use.

- `/oidc/payloads/*` stores every `oidc-provider` model in the new `oidc_payloads` table. A record tied to a session that is no longer live reads as absent, so any revocation ends provider access at once. Replay detection inserts only if absent, in one statement.
- `POST /oidc/sign` signs provider tokens with the separate `OIDC_JWKS_*` key set, and only for a live session holding a provider grant for that client, with the `acr`, `amr` and `auth_time` that session earned, identity claims equal to the account's own, no claims outside what the library issues, an audience the client may use (never the API or the provider itself) and the active key. `GET /oidc/jwks` publishes the public keys. The server refuses provider keys that reuse a first-party signing key.
- `GET /oidc/clients/:id`, `POST /oidc/clients/:id/verify-secret`, `GET /oidc/accounts/:id`, `GET /oidc/sessions/:id/auth-context`, `POST /oidc/sessions/:id/revoke`, `POST /oidc/events` and `GET /oidc/config` complete the contract from `@seamless-auth/types` 0.34.0.
- Every `/oidc/*` route answers only the internal service token, and answers 404 while the new `oidc_provider_enabled` system config key is off, which is the default. The server refuses to turn it on, through the admin API or the environment, unless `oidc_issuer` is https, differs from `ISSUER`, sits under `rpid`, and the provider keys are present.
- New tables `oidc_payloads`, `oidc_clients`, `oidc_resources` and `oidc_client_resources`, and new `sessions` columns `authMethods` and `authTime`. Sign-in now records the method that proved the user (with the passkey's backup state and user verification), and a refresh carries it forward.
- New system config keys and environment variables: `oidc_provider_enabled` (`OIDC_PROVIDER_ENABLED`), `oidc_issuer` (`OIDC_ISSUER`), `allow_client_secrets` (`OIDC_ALLOW_CLIENT_SECRETS`) and `third_party_clients_enabled` (`OIDC_THIRD_PARTY_CLIENTS_ENABLED`). New `oidc_*` auth event types.

Run the migrations before deploying. Nothing changes for a deployment that leaves the provider off. Requires `@seamless-auth/types` 0.34.0-next.0.
