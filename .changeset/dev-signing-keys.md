---
'seamless-auth-api': patch
---

Development signing keys are now created at startup, before the server listens, so `GET /.well-known/jwks.json` publishes a key from the first request. If no dev key can be read, the endpoint answers `{ "keys": [] }` and logs why, instead of a 500.

The dev key directory defaults to `./keys/dev` (`/app/keys/dev` in the image) and can be moved with `SEAMLESS_DEV_KEYS_DIR`. The bundled `docker-compose.yml` keeps `/app/keys` on a `dev-keys` volume, so a recreated container keeps its key. The public key is derived from `private.pem`, so only the private key has to survive.

The dev `kid` is no longer the constant `dev-main`. It is `dev-` followed by the first 16 characters of the key's RFC 7638 JWK thumbprint, so a regenerated key gets a new `kid` and adapters that cache the JWKS refetch it on their own. Anything that looks the dev key up by the literal `dev-main` should read the `kid` from the JWKS instead. The `kid` on adapter service tokens is not checked by the API and is unaffected.
