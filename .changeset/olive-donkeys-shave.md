---
'seamless-auth-api': minor
---

Add the FIDO2 conformance test interface behind an environment flag.

The FIDO2 conformance test tools drive a server through a fixed message interface
rather than through its own API, so with no such surface conformance
self-validation could not be run at all. That is the first gate of FIDO Functional
Certification, and the only part of it reachable without an assessor, a customer or
a sponsoring agency.

Four paths now serve that interface under `/conformance`, and only when
`FIDO_CONFORMANCE_MODE=true`. The flag is refused under `NODE_ENV=production`,
matching `DISABLE_AUTH_RATE_LIMITS` and `ALLOW_UNCREDENTIALED_DELIVERY_SECRETS`.
With the flag unset nothing is registered: the routes never reach Express, never
reach the OpenAPI document, and the paths answer the ordinary 404. Enforcement is
in the tests, not in the documentation, because the surface takes no
authentication, issues no sessions, honours whatever attestation conveyance the
caller asks for instead of the deployment policy, and is expected to accept
malformed input.

What a run validates is the shipping WebAuthn verification: the same library calls
the real controller makes, the same advertised algorithm list, and the same RP ID
and origins from `system_config`. Storage is not shared. Conformance users and
credentials are held in memory, because the tools invent hundreds of accounts and
replay ceremonies on purpose.

Three optional variables point metadata verification at the tools rather than the
production FIDO Metadata Service, which signs its blobs with a different root:
`FIDO_CONFORMANCE_MDS_URLS`, `FIDO_CONFORMANCE_MDS_ROOT_CERT_FILE` and
`FIDO_CONFORMANCE_METADATA_DIR`. Conformance mode also brings the metadata service
up whatever this deployment has configured, since the surface honours the
conveyance the tools ask for.
