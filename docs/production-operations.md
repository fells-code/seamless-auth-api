# Production Operations

Authentication infrastructure is security-sensitive. This guide covers public deployment guidance for self-hosted Seamless Auth API operators.

## Required Practices

- Use HTTPS end to end.
- Restrict CORS and WebAuthn origins to exact trusted origins.
- Keep access and refresh tokens out of browser-readable storage.
- Do not depend on browser auth cookies. Seamless Auth API uses a JSON/bearer token contract; put
  browser-facing token custody behind a trusted server adapter or backend.
- Store raw secrets in environment variables, a secret manager, or a user-supplied secret store.
- Back up Postgres and test restores.
- Monitor authentication failures and suspicious events.
- Keep route-level rate limits enabled.

## Secrets Inventory

Production deployments should define:

- `API_SERVICE_TOKEN`
- `REFRESH_TOKEN_LOOKUP_SECRET`
- `TOTP_SECRET_ENCRYPTION_KEY`
- `OAUTH_STATE_SECRET`
- `SEAMLESS_JWKS_ACTIVE_KID`
- `SEAMLESS_JWKS_KEY_<kid>_PRIVATE`
- `JWKS_PUBLIC_KEYS`
- OAuth client-secret environment variables referenced by provider `clientSecretEnv`
- Messaging provider credentials when direct delivery is enabled

Do not store raw secrets in `system_config`.

## Signing Keys

Access tokens are signed with configured JWKS signing keys. A typical rotation is:

1. Generate a new key pair.
2. Publish the new public key in `JWKS_PUBLIC_KEYS`.
3. Deploy with both old and new public keys available.
4. Switch `SEAMLESS_JWKS_ACTIVE_KID` to the new key id.
5. Keep retired public keys until all tokens signed with them expire.
6. Remove retired public keys after the token TTL window.

## Refresh Tokens

Refresh tokens are opaque values. The API stores hashes and lookup fingerprints, not raw refresh tokens.

Use a stable `REFRESH_TOKEN_LOOKUP_SECRET` in production. Rotating it without dual-lookup support requires revoking existing sessions or running a planned migration.

## TOTP Secrets

TOTP secrets are encrypted at rest. Use `TOTP_SECRET_ENCRYPTION_KEY` in production instead of relying on development fallbacks.

If rotating the TOTP encryption key, decrypt and re-encrypt stored secrets in a controlled migration. If the old key is unavailable, users must re-enroll TOTP.

## OAuth Secrets

OAuth provider client secrets live in environment variables referenced by `clientSecretEnv`. Rotate them at the provider and update the deployed environment value. Do not enter client secret values into runtime system config or admin UI fields.

## Messaging Credentials

Direct email/SMS delivery requires provider credentials. If you use an external trusted server adapter for delivery, keep delivery tokens on that server and avoid returning delivery payloads to browsers.

## Redaction

Logs and auth events redact sensitive metadata by default. Sensitive values include tokens, OTPs, magic-link URLs, OAuth state/codes, PRF salts and output, TOTP secrets, email/phone snapshots, private keys, and configured provider secrets.

Public admin/user responses are also minimized. They should not expose WebAuthn public keys,
refresh-token hashes/lookups, challenge context, verification tokens, PRF output, TOTP secrets, or
provider tokens.
