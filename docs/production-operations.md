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
- Verify the signature of the container image you deploy, and deploy it by digest.

## Verifying the Container Image

Release images are built by `.github/workflows/docker-publish.yml`, which `release.yml` calls on
`main` after the version PR merges. For every release from v0.8.0 the workflow:

- builds `linux/amd64` and `linux/arm64` with Docker Buildx and attaches an SPDX SBOM and a SLSA
  provenance statement (`sbom: true`, `provenance: mode=max`) to the image index,
- signs the image index digest with cosign keyless signing. The certificate is issued to the
  workflow's GitHub OIDC identity, so there is no long-lived signing key.

The examples use v0.19.1. Substitute the tag you deploy. You need
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/) v2, Docker with Buildx, and jq.
If you would rather not install cosign, the official image works the same way:
`docker run --rm ghcr.io/sigstore/cosign/cosign:v2.4.1 verify ...`.

### 1. Resolve the tag to a digest

Tags can be moved; digests cannot. Resolve once and use the digest for every step and for the
deployment itself.

```bash
IMAGE=ghcr.io/fells-code/seamless-auth-api
DIGEST=$(docker buildx imagetools inspect "$IMAGE:v0.19.1" --format '{{ json .Manifest }}' | jq -r .digest)
echo "$IMAGE@$DIGEST"
```

### 2. Verify the signature

```bash
cosign verify "$IMAGE@$DIGEST" \
  --certificate-identity-regexp '^https://github\.com/fells-code/seamless-auth-api/\.github/workflows/docker-publish\.yml@refs/(heads/main|tags/v.*)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

A passing check proves the digest was signed by `docker-publish.yml` running in
`fells-code/seamless-auth-api` on GitHub Actions, and that the signature is recorded in the public
Rekor transparency log. The identity is the called workflow, at `refs/heads/main` for releases cut
by `release.yml`, or at the tag for a release started by pushing a tag by hand. Do not loosen the
regexp to the whole repository: that would accept an image signed by any workflow on any branch.

cosign prints the verified signatures as JSON on stdout. Its `.[0].optional.githubWorkflowSha` field is
the commit the image was built from, which should match the release tag:

```bash
git ls-remote https://github.com/fells-code/seamless-auth-api refs/tags/v0.19.1
```

### 3. Read the SBOM

```bash
docker buildx imagetools inspect "$IMAGE@$DIGEST" --format '{{ json .SBOM }}' > sbom.json
jq '.["linux/amd64"].SPDX.packages | length' sbom.json
```

The output has one SPDX 2.3 document per platform (`linux/amd64`, `linux/arm64`). Feed
`.["linux/amd64"].SPDX` to a scanner such as Grype or Trivy to check it against current advisories.

### 4. Read the provenance

```bash
docker buildx imagetools inspect "$IMAGE@$DIGEST" --format '{{ json .Provenance }}' > provenance.json
jq '.["linux/amd64"].SLSA | {
  builder: .runDetails.builder.id,
  revision: .buildDefinition.externalParameters.request.args["label:org.opencontainers.image.revision"],
  version: .buildDefinition.externalParameters.request.args["label:org.opencontainers.image.version"]
}' provenance.json
```

`builder` is the GitHub Actions run that produced the image, and `revision` is the source commit.

The SBOM and provenance are BuildKit attestations stored inside the image index. They are not
signed separately: they are covered by the cosign signature because the signed index references
each attestation manifest by digest. Always read them by the digest you verified in step 2. There
is no GitHub artifact attestation for the image, so `gh attestation verify` does not apply.

## Secrets Inventory

Production deployments should define:

- `SEAMLESS_SERVICE_TOKEN` (the older `API_SERVICE_TOKEN` name is still accepted as a fallback)
- `REFRESH_TOKEN_LOOKUP_SECRET`
- `TOTP_SECRET_ENCRYPTION_KEY`
- `OAUTH_STATE_SECRET`
- `SEAMLESS_JWKS_ACTIVE_KID`
- `SEAMLESS_JWKS_KEY_<kid>_PRIVATE`
- `SEAMLESS_JWKS_PUBLIC_KEYS`
- `SEAMLESS_OIDC_SERVICE_TOKEN`, `OIDC_JWKS_ACTIVE_KID` and `OIDC_JWKS_KEYS`, when the OpenID
  Provider is enabled. Give the provider service `SEAMLESS_OIDC_SERVICE_TOKEN` only, never the
  adapters' `SEAMLESS_SERVICE_TOKEN`.
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

### OpenID Provider keys

The provider has its own key set, `OIDC_JWKS_KEYS`, so a provider token can never verify as a
first-party one. Every key in the set is published at `/oidc/jwks`, which the provider service
serves as its public `/jwks`, and only `OIDC_JWKS_ACTIVE_KID` signs. Rotation follows the same
three steps:

1. **Add.** Add the new private JWK to `OIDC_JWKS_KEYS` and deploy. It is published, and the
   outgoing key still signs. Wait until relying parties have refreshed their cached JWKS.
2. **Flip.** Point `OIDC_JWKS_ACTIVE_KID` at the new key and deploy.
3. **Retire.** Once the longest provider token lifetime has passed, remove the outgoing key and
   deploy.

## Secrets Separate From The Service Token

`REFRESH_TOKEN_LOOKUP_SECRET`, `TOTP_SECRET_ENCRYPTION_KEY`, `OAUTH_STATE_SECRET` and
`DECOY_SUBJECT_SECRET` no longer fall back to the service token. In production the refresh lookup
and decoy secrets are always required, the TOTP key once any TOTP credential exists, and the state
secret once an OAuth provider is configured. The server refuses to start without the ones it needs
and names each.

Upgrading a deployment that relied on the fallback (before v0.20), in this order:

1. Set each missing variable to the **current** service token value and deploy v0.20. Stored
   refresh token fingerprints and TOTP secrets were made with that value, so nothing changes.
2. Give each one a value of its own before the service token is next rotated, then rotate the
   service token freely. Changing the refresh lookup secret signs everyone out and changing the
   TOTP key makes stored TOTP secrets unreadable, so change those two only deliberately.

Do not set them to new values in step 1: existing sessions and TOTP enrollments would stop
working.

Refresh tokens are opaque values. The API stores hashes and lookup fingerprints, not raw refresh tokens.

Use a stable `REFRESH_TOKEN_LOOKUP_SECRET` in production. Rotating it without dual-lookup support requires revoking existing sessions or running a planned migration.

## TOTP Secrets

TOTP secrets are encrypted at rest with a key derived from `TOTP_SECRET_ENCRYPTION_KEY`, which production requires once TOTP is in use.

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
