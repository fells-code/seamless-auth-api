---
'seamless-auth-api': minor
---

Generate a real typed client from OpenAPI. `src/generated/api.ts` was an empty
openapi-typescript stub (`paths = Record<string, never>`) with no way to regenerate it. It now
carries the full contract, generated from the live route definitions along with a committed
`openapi.json`.

`npm run generate:api` produces both. It loads the route modules into a throwaway Express app to
populate the OpenAPI registry, so no server, environment, or database is needed, and it refuses to
write an empty spec. Output is prettier-formatted so regenerating never leaves the tree failing
`format:check`.

Both artifacts are covered by a test that rebuilds the document and compares it to what is
committed, so a route or schema change that is not regenerated fails CI instead of silently
drifting. The comparison ignores `info.version`, which tracks `package.json` and is bumped by
Changesets on release.
