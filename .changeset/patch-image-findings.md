---
'seamless-auth-api': patch
---

Close the open Trivy findings on the release image. The runtime stage now applies Debian
security updates at build time, so fixes such as the pcre2 out-of-bounds reads
(CVE-2026-86145, CVE-2026-89161) land without waiting for the node base image to be
rebuilt. `qs` moves to 6.16.0 and `uuid` (pulled in by sequelize) is overridden to 11.1.1.
