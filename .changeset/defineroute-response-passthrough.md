---
'seamless-auth-api': patch
---

Fix response schema handling so a controller response that fails its declared schema is no longer overwritten. Previously the API replaced the real body with a generic `Response validation failed` object and leaked internal Zod issues to clients. It now logs the drift server-side and returns the controller's intended response unchanged.
