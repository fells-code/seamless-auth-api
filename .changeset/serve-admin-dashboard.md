---
'seamless-auth-api': minor
---

Serve the admin dashboard SPA at the `/admin` subpath on the API's own origin. Static serving is additive and gated behind `SERVE_ADMIN_DASHBOARD` (enabled by default): the admin API routes are registered first and keep priority, and an SPA history fallback returns the dashboard `index.html` for unmatched `/admin` and `/admin/*` navigations, with correct MIME types, long-lived immutable caching for hashed assets, and `no-store` on the shell. The Docker image builds the dashboard from a pinned git ref (the `SEAMLESS_ADMIN_DASHBOARD_REF` build ARG) with base path `/admin` and copies it into the runtime image. No CORS changes are needed because the dashboard is same-origin.
