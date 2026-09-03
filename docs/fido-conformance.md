# Running the FIDO2 conformance tools

Conformance self-validation is the first gate of FIDO Functional Certification, and
the only part of it that can be done without an assessor, a customer or a sponsoring
agency. This page is how to run it against a local instance.

## What the interface is

The FIDO2 conformance test tools drive a server through a fixed message interface
rather than through the server's own API. This repository serves that interface at
four paths:

| Path                                    | Purpose                |
| --------------------------------------- | ---------------------- |
| `POST /conformance/attestation/options` | Registration options   |
| `POST /conformance/attestation/result`  | Registration result    |
| `POST /conformance/assertion/options`   | Authentication options |
| `POST /conformance/assertion/result`    | Authentication result  |

Every response carries the conformance envelope, `status` plus `errorMessage`, with
the options payload merged in alongside on the two options endpoints.

## It is off unless you turn it on

The interface is mounted only when `FIDO_CONFORMANCE_MODE=true`, and the flag is
refused outright under `NODE_ENV=production`. With the flag unset the routes are
never registered: they do not reach Express, they do not reach the OpenAPI document,
and the paths answer the ordinary 404. That is enforced by
[the mounting tests](../tests/integration/conformance/conformance.spec.ts) rather
than left to this page.

This matters because the surface is deliberately weaker than the shipping one. It
takes no authentication, it issues no sessions or tokens, it honours whatever
attestation conveyance and authenticator selection the caller asks for instead of
the deployment's authenticator policy, and it is expected to accept malformed input
without failing the request outright. None of that belongs in a customer deployment.

## What it shares with the real server, and what it does not

Shared, because these are what a conformance run exists to validate:

- `verifyRegistrationResponse` and `verifyAuthenticationResponse`, the same calls
  the shipping WebAuthn controller makes
- [`SUPPORTED_ALGORITHM_IDS`](../src/lib/webauthnAlgorithms.ts), so a run exercises
  the advertised algorithm list itself rather than a copy of it
- `rpid` and `origins` from `system_config`
- The FIDO Metadata Service wiring

Not shared: storage. Conformance users and credentials live in memory for the life
of the process, in [`conformanceStore.ts`](../src/services/conformanceStore.ts). The
tools invent hundreds of accounts and replay ceremonies on purpose, and none of that
belongs in the tables a real deployment authenticates against.

The conformance API sends a username only on the options request, so a result is
matched back to its ceremony by the challenge inside `clientDataJSON`. No session
cookie is involved, and a ceremony is spent on lookup, so a challenge cannot be
answered twice.

## Running a local instance

1. Register for tool access on the FIDO Alliance certification site and install the
   conformance tools.

2. Configure this server for the origin and RP ID the tools will use. Both come from
   `system_config`, so `.env` alone is not enough on an instance that has already
   bootstrapped: see [configuration.md](./configuration.md). For a fresh local
   instance:

   ```
   APP_ORIGINS=http://localhost:8080
   RPID=localhost
   ```

   `FRONTEND_URL` is also required, or the process exits at startup before any of
   this matters. Set `AUTHENTICATOR_POLICY` with `attestation` set to `direct`: the
   conformance surface honours whatever conveyance the tools ask for, but
   `requireKnownAuthenticator` is what puts the metadata service into strict mode,
   which is the posture a run is meant to exercise.

3. Turn the interface on, and turn the auth rate limiters off. A conformance run
   drives hundreds of ceremonies from one IP and will otherwise be throttled.

   ```
   FIDO_CONFORMANCE_MODE=true
   DISABLE_AUTH_RATE_LIMITS=true
   RATE_LIMIT=100000
   ```

4. Start the server with `npm run dev`. The log carries a warning naming the mounted
   surface, which is the confirmation that the flag took effect.

5. In the tools, set the server URL to the base path, including the prefix:

   ```
   http://localhost:5312/conformance
   ```

   The tools append `/attestation/options` and the rest to whatever base URL they are
   given.

## Metadata tests

The tools serve their own MDS3 endpoints and sign those blobs with their own root
certificate, so a server that trusts only the production FIDO root fails every
metadata test with a certificate error. Three optional variables point verification
at the run instead, and all three are read only in conformance mode:

| Variable                              | What it is                                       |
| ------------------------------------- | ------------------------------------------------ |
| `FIDO_CONFORMANCE_MDS_URLS`           | Comma separated MDS3 endpoints the run stands up |
| `FIDO_CONFORMANCE_MDS_ROOT_CERT_FILE` | PEM the run signs its blobs with                 |
| `FIDO_CONFORMANCE_METADATA_DIR`       | Directory of metadata statement JSON files       |

Get the endpoint list by asking the tools' own service for it, passing the same base
URL you will give the tools:

```
curl -X POST https://mds3.fido.tools/getEndpoints \
  -H 'Content-Type: application/json' \
  -d '{"endpoint":"http://localhost:5312/conformance"}'
```

The root certificate is the FIDO test root published at
`https://mds3.fido.tools/pki/MDS3ROOT.crt`. That page asks not to be fetched at
runtime, so save a copy and point the variable at the file.

Statements are accepted both bare and wrapped in an MDS entry, and the directory is
read recursively, so the "DOWNLOAD SERVER METADATA" archive can be unzipped and
dropped in unedited: it expands to a nested `metadataStatements/` directory. A
statement that cannot be read is skipped with a line in the log rather than taken
down the whole boot.

Check the log for `Loaded N local conformance metadata statements` before running.
Loading nothing is the failure that looks least like one: with
`requireKnownAuthenticator` set the metadata service runs in strict mode, so every
conformance authenticator is refused as unlisted, every registration fails, and the
tests that fail are the ones that depend on a registration having succeeded rather
than the metadata tests themselves.

Conformance mode also clears the preset Apple, Android Key and SafetyNet root
certificates. The tools sign those statements with their own test roots, so
validating against the real vendor roots cannot succeed; cleared, the roots carried
in the metadata statement are used instead.

Conformance mode also brings the metadata service up regardless of whether this
deployment requests attestation, because the conformance surface honours the
conveyance the tools ask for rather than the deployment policy.

## Scheduling, which is the part that bites

- Self-validation results must reach the Certification Secretariat **at least 14
  days** before an interoperability event.
- Interoperability testing must happen **within 90 days** of a successful
  self-validation.

Register for tool access early and run the tools iteratively. Treat a successful
self-validation as the trigger for scheduling interop, not as a milestone to rush:
the 90 day clock starts there.
