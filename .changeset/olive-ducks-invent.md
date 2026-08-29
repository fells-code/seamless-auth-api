---
'seamless-auth-api': patch
---

Scan, describe and sign the published container image.

Adopters pulling `ghcr.io/fells-code/seamless-auth-api` had no way to verify what
was inside a tag or that it came from this repository. The release workflow now:

- Builds the image and scans it with Trivy **before** it is pushed, failing on
  fixable high or critical findings, and reports the findings to the security tab
- Attaches an SPDX SBOM and a provenance attestation to the image, so the
  registry can answer what is inside a tag and where it was built
- Signs the pushed digest with cosign, keyless, so there is no signing key to
  store or rotate
- Prints the digest and the exact verification commands to the job summary

Unfixed findings do not block, and neither do npm's own bundled dependencies
inside the Node base image, which the container never invokes and which no change
here can patch. Verified against `node:24-slim`: without that exclusion the gate
fails on four findings in npm's own tree on the first release. The application's
own dependencies are still scanned and still block, which is the part this
repository controls. A gate that blocks on something nobody can fix only trains
people to bypass it.
