---
'seamless-auth-api': patch
---

Build and run the Docker image on Node 24 (`node:24-slim`) to match the
package's `engines.node` (`>=24 <25`). The image previously used `node:20-slim`,
which triggered EBADENGINE warnings and could crash the container at startup,
including in the CLI conformance harness.
