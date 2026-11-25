---
'seamless-auth-api': minor
---

Magic links now need a code from the link fragment to sign in, and a requested `redirectUri` must match exactly (#594).

Breaking, in two places:

- `redirectUri` on `POST /magic-link` is no longer accepted on its origin alone. With `magic_link_redirect_uris` empty, the only accepted value is the `/verify-magiclink` page on `frontend_url` or a configured origin, spelled exactly with no query. Any other path, such as a mobile landing page, has to be listed in `magic_link_redirect_uris`.
- The link is now `...?token=<token>#code=<code>`. `GET /magic-link/verify/:token` no longer consumes the link, even on the device that requested it: it always answers `409 confirmation_required`, with a new `sameDevice` boolean. `POST /magic-link/verify/:token/confirm` now requires a JSON body `{ "code": "<code>" }` and answers `400` without it. A wrong code spends the link. Links mailed before the upgrade carry no code and can no longer be completed, so a user with one in flight requests another.

Clients need to read `code` from the fragment, confirm with it, and confirm without asking when `sameDevice` is true. Release a client that does this before upgrading the API: it keeps working against older API versions, which ignore the body. A caller using external delivery that builds its own URL from `delivery.token` has to switch to `delivery.magicLinkUrl`, which carries the code.

Run the database migrations: this adds `magic_link_tokens.code_hash`.
