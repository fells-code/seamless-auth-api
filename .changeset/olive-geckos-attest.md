---
'seamless-auth-api': minor
---

Make `requireKnownAuthenticator` refuse a credential that cannot be looked up,
and stop claiming attestation was verified when it was not.

**Behaviour change.** A deployment running `attestation: 'direct'` with
`requireKnownAuthenticator: true` now refuses a credential that self attests or
presents no attestation. Authenticators that ship no attestation certificate can
no longer enrol there. Both settings are off by default, so only a deployment
that explicitly asked for known authenticators is affected, which is the
population the change is for.

The setting only ever set the metadata service to a strict verification mode, and
that mode is consulted per attestation format, only for a statement carrying a
certificate chain. Every format requires one except `packed`, which is also
defined without: a statement the credential signs with its own key. Nothing
stands behind such a statement and nothing can be looked up for it, so a
credential presenting one was admitted without the setting ever being consulted.
An agency that had asked for known authenticators only was getting no
restriction at all against exactly the authenticators the setting exists to keep
out. The refusal reuses the existing `authenticator_not_allowed` error, with the
reason recorded in the audit event.

The rule applies only under `direct`. Under `none` no credential presents a
chain, so it would refuse every registration rather than restrict anything, and
the server now logs that misconfiguration at startup the way it already does for
an allow list set without attestation.

`credentials.attestationVerified` is now true only when the metadata service
actually held a statement for the credential's AAGUID. It was derived from the
attestation format and whether the service had come up, so a self attested
credential was recorded as verified against metadata it had never been compared
to. That field exists so an audit can tell an unattested credential from a
checked one, and it could not.

A new nullable `credentials.attestationType` column records `none`, `self` or
`basic`. The format alone cannot separate the last two, since a
manufacturer-signed statement and one a credential signed for itself are both
`packed`. Existing rows are left null; neither value can be recovered after the
fact.
