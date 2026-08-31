---
'seamless-auth-api': minor
---

Read the JWKS public keys document under one name, and document rotation properly.

**Fixes a deployment trap.** `validateEnvs.sh` required `JWKS_PUBLIC_KEYS`, and the
configuration reference and `.env.example` named only that, but token verification read
`SEAMLESS_JWKS_PUBLIC_KEYS`. A deployment that set exactly what this API asked for
started cleanly and then threw on every JWT verification, because
`getPublicKeyByKid` could not find the secret. The failure arrives at the first
authenticated request rather than at boot, which is the worst place for it.

Everything now uses `SEAMLESS_JWKS_PUBLIC_KEYS`: the entrypoint check, the
`/.well-known/jwks.json` handler, the configuration reference, and `.env.example`.

**Breaking for anyone setting only the unprefixed name**, who is already broken and
does not know it. After this they fail to start, with the variable named, instead of
serving a deployment that cannot verify a token it just issued.

**Rotation is documented rather than implemented.** The acceptance criteria in the
rotation issue are met by the read path that already exists: the document is a list,
every key in it is published and can verify, and only the active kid signs. What was
missing was a written procedure, which `docs/production-operations.md` now carries as
the three-step overlap (add, flip, retire), including why the steps cannot be
collapsed and why key ids must be environment-variable safe.

The server deliberately does not rotate its own keys. It has no secret-store write
path, and environment variables are fixed for a process's lifetime, so a server that
rotated could not observe the result without a restart it cannot trigger. The document
belongs to whatever manages the secrets.

Accordingly the empty `ensureKeys()` production branch is removed, along with
`initKeys`, their specs and the dev-stack invocation. It advertised a runtime rotation
capability that is not going to exist, and its development branch wrote a keypair to
`./keys` that nothing has ever read: `signingKeyStore` keeps dev keys under
`./keys/dev` and generates them lazily.
