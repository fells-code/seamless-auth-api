---
'seamless-auth-api': patch
---

Load the conformance metadata statements the FIDO tools actually ship, and let
their attestation statements validate.

Two defects in conformance mode, both found by the first real run of the FIDO2
Conformance Test Tools:

- **Statements were never loaded.** The tools' "DOWNLOAD SERVER METADATA" archive
  unzips to a nested `metadataStatements/` directory, and the loader only read
  JSON files at the top level of `FIDO_CONFORMANCE_METADATA_DIR`. It silently
  found none. With `requireKnownAuthenticator` set, the metadata service runs in
  strict mode, so every conformance authenticator was refused as unlisted and
  every registration failed. The loader now recurses, so the archive can be
  dropped in unedited as the documentation already promised.
- **Vendor attestation roots blocked their own tests.** The tools sign Apple,
  Android Key and SafetyNet statements with their own test roots, so validating
  them against the real vendor roots could never succeed. Those preset roots are
  now cleared in conformance mode, which lets the library fall back to the roots
  carried in the metadata statement.

- **Registration options advertised an extension nobody asked for.**
  `generateRegistrationOptions` always appends its own `credProps`, and the tools
  compare the echoed extensions to the requested set for exact equality, so a
  request for `{"example.extension.bool": true}` came back as that plus
  `credProps` and failed. The requested set is now echoed verbatim. The
  authentication options path never had the problem, since the library passes
  extensions through there unchanged.

All three are confined to `FIDO_CONFORMANCE_MODE`, which is refused under a
production `NODE_ENV`. No deployed behaviour changes.
