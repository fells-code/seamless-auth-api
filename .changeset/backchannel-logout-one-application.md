---
'seamless-auth-api': minor
---

Back-channel logout now reaches an application whose grant ends while the first-party session goes on (#543). When the provider service deletes a `Grant` (the user chooses "only sign out of this app", or the grant is revoked), the API sends that application a logout token for the `sid` it was given, with the same sender and the same `oidc_backchannel_logout_sent` and `oidc_backchannel_logout_failed` events as a session logout. Other applications on the session are not told, and nothing is sent while another live grant still signs the application in on that session. Applications that register a `backchannel_logout_uri` should expect a logout token for a partial logout as well as a full one.
