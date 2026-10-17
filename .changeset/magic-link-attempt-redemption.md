---
'seamless-auth-api': minor
---

Magic link sign-in issues one session per confirmed link, to the attempt that requested it, and a link opened on another device needs the person who opened it to confirm (GHSA-9jg2-jjqq-3346).

- Each link records the `jti` of the ephemeral token that requested it, and `GET /magic-link/check` only looks up links for the polling attempt. Another ephemeral token for the same address cannot collect it.
- The first check after the link is confirmed issues the session and marks the link redeemed. Later checks for the same attempt answer `200 { "message": "Success" }` without tokens, so a second tab in the same browser still sees the sign-in complete and reads the session it already has.
- `GET /magic-link/verify/{token}` consumes the link only when it is opened on the requesting device: proven by the requesting attempt's ephemeral bearer token when the adapter forwards it, otherwise by the IP address and user agent a trusted adapter forwards with its service token. A fingerprint no adapter vouched for does not count, since behind an adapter that does not forward client context every request carries the adapter's own address. Opened anywhere else it answers `409 confirmation_required` with the requesting platform and time, and leaves the link unused, so a mail scanner or a click on a link someone else requested no longer signs that someone in.
- New `POST /magic-link/verify/{token}/confirm` consumes the link after the person who opened it approves.
- New auth event `magic_link_confirmation_required`.
- A request or poll with an ephemeral token that has no `jti` is refused with `400`.
- Migration: `magic_link_tokens` gains `attempt_id`, `requested_device_class` and `redeemed_at`. Links requested before the upgrade can no longer be used; they expire within fifteen minutes.

Breaking for clients: a link opened on a different device now needs a confirmation screen. SDK versions without one show the 409 as an error, and the link stays usable for the requesting device's own browser.
