---
'seamless-auth-api': patch
---

Build the magic-link redirect from a dedicated frontend URL. Add an optional
`frontend_url` system config (env `FRONTEND_URL`) and use it as the base for
emailed magic links, falling back to `origins[0]` when unset. Previously the
link was always built from the first configured origin, which could point at a
non-frontend origin (for example an API host) depending on origin ordering.
