---
'seamless-auth-api': patch
---

Pin `glob` to 14.0.3 and `minimatch` to 11.0.3 through npm overrides for GHSA-3g3m-2fjr-6pw4 and GHSA-g3hv-75wg-m249 (both moderate). The production dependency audit is now clean. `@redocly/openapi-core` 1.x, used only by the OpenAPI type generator, keeps `minimatch` 5.1.9 because it calls the old default export, so that one dev-only finding remains until `openapi-typescript` moves to `@redocly/openapi-core` 2.
