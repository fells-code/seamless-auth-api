---
'seamless-auth-api': patch
---

Drop the orphaned bootstrap secret check from the container entrypoint.

`validateEnvs.sh` still required `SEAMLESS_BOOTSTRAP_SECRET` whenever `SEAMLESS_BOOTSTRAP_ENABLED`
was `true`. Both variables were removed with the admin bootstrap invite flow, so nothing in the
runtime reads either one. A deployment that carried the old `SEAMLESS_BOOTSTRAP_ENABLED=true` over
from a previous release refused to boot until it supplied a secret that no longer did anything.
