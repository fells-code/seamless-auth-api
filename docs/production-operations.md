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

- `SEAMLESS_SERVICE_TOKEN` (the older `API_SERVICE_TOKEN` name is still accepted as a fallback)
- `REFRESH_TOKEN_LOOKUP_SECRET`
- `TOTP_SECRET_ENCRYPTION_KEY`
- `OAUTH_STATE_SECRET`
- `SEAMLESS_JWKS_ACTIVE_KID`
- `SEAMLESS_JWKS_KEY_<kid>_PRIVATE`
- `SEAMLESS_JWKS_PUBLIC_KEYS`
- OAuth client-secret environment variables referenced by provider `clientSecretEnv`
- Messaging provider credentials when direct delivery is enabled

Do not store raw secrets in `system_config`.

## Signing Keys

### What the server does, and does not do

`SEAMLESS_JWKS_PUBLIC_KEYS` holds **every** published key, not just the active one. The server
treats it as a list:

- `/.well-known/jwks.json` publishes all of them.
- Token verification resolves a key by the `kid` in the token's own header, so any published key
  can verify a token it signed.
- Only `SEAMLESS_JWKS_ACTIVE_KID`, and that key's private half, is used to sign.

That separation is what makes rotation an overlap rather than a cutover. Nothing has to be
invalidated to change signing keys.

**The server never writes any of this.** It has no secret-store write path and no cloud SDK, and
environment variables are fixed for a process's lifetime, so a server that rotated its own keys
could not observe the result without a restart it cannot trigger. Whatever manages your secrets
owns the document; the server reads it.

### Rotating without downtime

Three steps, each one deployed before the next. Do not collapse them: the overlap is the whole
mechanism.

1. **Add.** Generate a key pair, add its public half to `SEAMLESS_JWKS_PUBLIC_KEYS`, and deploy.
   The outgoing key still signs. Verifiers now accept both.
2. **Flip.** Point `SEAMLESS_JWKS_ACTIVE_KID` at the new key id, inject its
   `SEAMLESS_JWKS_KEY_<kid>_PRIVATE`, and deploy. The new key signs. Tokens already issued keep
   verifying, because the outgoing public key is still published.
3. **Retire.** Once `access_token_ttl` has passed, so no token signed by the outgoing key can still
   be live, remove it from the document and drop its private key. Deploy. Access tokens are the
   longest-lived signed tokens (ephemeral tokens last five minutes). Refresh tokens are opaque and
   not signed, so rotation never affects them.

Each step needs a restart to take effect, because the values arrive as environment variables. The
server re-reads the document every five minutes within a process, which covers a secret updated in
place, but a changed environment variable needs a new process.

Key ids must be letters, digits and underscores, and must not start with a digit, because the
private-key variable name is derived from the id: `SEAMLESS_JWKS_KEY_<kid>_PRIVATE`. A key id with
a hyphen produces a variable name that cannot be set.

### Managed deployments

For instances built with `seamless-iac`, this is already automated and should not be done by hand.
Terraform owns the document, signing keys are a set of labels with `jwks_active_key_label`
selecting the signer, and the three steps above are three applies. See ADR 0011,
`Terraform owns the JWKS document, and rotation overlaps`, and the procedure in that repo's
`portal-auth/README.md`.

## Secrets That Fall Back To The Service Token

`REFRESH_TOKEN_LOOKUP_SECRET`, `TOTP_SECRET_ENCRYPTION_KEY`, `OAUTH_STATE_SECRET` and
`DECOY_SUBJECT_SECRET` each fall back to the service token (`SEAMLESS_SERVICE_TOKEN`, or
`API_SERVICE_TOKEN`) when unset, and the server logs a warning at boot naming each one that does.
The server adapter holds the service token as well, so it is the secret most likely to need
rotating, and while the others share it, rotating it signs everyone out and makes every stored TOTP
secret unreadable.

To separate them without breaking anything, in this order:

1. Set each of the four variables to the **current** service token value and redeploy. Nothing
   changes yet, because each one already resolves to that value.
2. Rotate the service token: set the new value on the API and on every server adapter.

The fallback is deprecated. From v0.20 each secret is required whenever the feature that uses it
is in use (TOTP for the encryption key, OAuth sign-in for the state secret, and always for the
refresh lookup and decoy secrets), so do this before upgrading to v0.20.

From then on the service token can be rotated freely. Do not set the four to new values in step 1:
stored refresh token fingerprints and TOTP secrets were made with the old key and would stop
matching.

Refresh tokens are opaque values. The API stores hashes and lookup fingerprints, not raw refresh tokens.

Use a stable `REFRESH_TOKEN_LOOKUP_SECRET` in production. Rotating it without dual-lookup support requires revoking existing sessions or running a planned migration.

## TOTP Secrets

TOTP secrets are encrypted at rest. Use `TOTP_SECRET_ENCRYPTION_KEY` in production instead of relying on development fallbacks.

If rotating the TOTP encryption key, decrypt and re-encrypt stored secrets in a controlled migration. If the old key is unavailable, users must re-enroll TOTP.

## OAuth Secrets

OAuth provider client secrets live in environment variables referenced by `clientSecretEnv`. Rotate them at the provider and update the deployed environment value. Do not enter client secret values into runtime system config or admin UI fields.

## Messaging Credentials

Direct email/SMS delivery requires provider credentials. If you use an external trusted server adapter for delivery, keep delivery tokens on that server and avoid returning delivery payloads to browsers.

## Running More Than One Instance

Everything that has to agree between instances lives in Postgres: sessions and refresh rotation
(the rotation claim is a single statement the database serialises), the lockout counter
(`auth_failures`), OTP codes, magic links, WebAuthn challenges, `system_config` and the audit trail.
Several instances behind a load balancer share all of it.

Some state is held in each process, and with more than one instance it behaves differently:

| State                             | Where                                                                                                 | With N instances                                                                                                                                                                                                                                                                                 |
| --------------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Rate limit and slow-down counters | `express-rate-limit` and `express-slow-down` in-memory stores ([`src/middleware`](../src/middleware)) | Each instance counts on its own, so a client whose requests are spread across instances gets up to N times the configured budget. Route by client address at the load balancer, or enforce a limit at the proxy as well.                                                                         |
| `system_config` cache             | Five minutes per process ([`getSystemConfig.ts`](../src/config/getSystemConfig.ts))                   | A config write clears the cache only on the instance that served it. The others keep the old values (roles, origins, login methods, lockout policy, token lifetimes) for up to five minutes. Restart the instances when a change must apply at once.                                             |
| OAuth `state` replay cache        | Consumed states, for ten minutes ([`oauthService.ts`](../src/services/oauthService.ts))               | A state is refused a second time only by the instance that consumed it, so another instance could accept a replayed callback within those ten minutes. The state is still HMAC signed, bound to its provider and expires after ten minutes, and the provider's authorization code is single use. |
| Audit degraded flag               | Five minutes after a failed audit write ([`auditHealth.ts`](../src/services/auditHealth.ts))          | `/health/status` reports `degraded` only on the instance whose write failed. Monitor every instance, not one.                                                                                                                                                                                    |

## Redaction

Logs and auth events redact sensitive metadata by default. Sensitive values include tokens, OTPs, magic-link URLs, OAuth state/codes, PRF salts and output, TOTP secrets, email/phone snapshots, private keys, and configured provider secrets.

Public admin/user responses are also minimized. They should not expose WebAuthn public keys,
refresh-token hashes/lookups, challenge context, verification tokens, PRF output, TOTP secrets, or
provider tokens.
