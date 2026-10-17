---
'seamless-auth-api': patch
---

`openapi.json` and `adapter-manifest.json` now carry the package version. The release version step regenerates both, and the contract test fails when either file drifts from the route definitions or from `package.json`. Both said 0.17.0 through the 0.18.0 release.
