# Security Policy for Seamless Auth API

Thank you for taking the time to help make Seamless Auth API more secure.

Seamless Auth API is a security-sensitive project used to protect authentication flows. As an open-source project, we take vulnerability reporting seriously.

---

## Supported Versions

Seamless Auth API is pre-1.0. Security fixes land on `main` and ship in the next release of the
latest minor line. Older minor lines do not receive backports, so the fix for a vulnerability is
to upgrade.

| Version          | Supported |
| ---------------- | --------- |
| 0.19.x (latest)  | Yes       |
| 0.18.x and older | No        |

Under 0.x a minor release can contain breaking changes. Read the
[CHANGELOG](./CHANGELOG.md) before upgrading across a minor version.

Fixed vulnerabilities are disclosed as
[GitHub security advisories](https://github.com/fells-code/seamless-auth-api/security/advisories),
each naming the affected and patched versions.

---

## Reporting a Vulnerability

If you believe you’ve found a security issue, **please do NOT open a public GitHub issue**.
Report it privately, by either of these routes:

- **GitHub private vulnerability reporting (preferred):** open
  [a new private report](https://github.com/fells-code/seamless-auth-api/security/advisories/new)
  from the repository's Security tab. The report, the discussion and the eventual advisory stay in
  one place.
- **Email:** **security@fellscode.com**, subject `Security Issue: seamless-auth-api`.

When possible, include the following information in your report:

- A clear description of the issue
- Steps to reproduce (proof of concept if available)
- Affected versions or commits
- Suggested mitigation (optional)

If the issue is in the browser-facing layer (cookies, CSRF, the session cookie lifecycle), it most
likely belongs to the server adapter,
[seamless-auth-server](https://github.com/fells-code/seamless-auth-server). Reporting it here is
fine; it will be moved to the right repository.

---

## What to Expect

The project has a single maintainer, so these are targets rather than guarantees:

1. We aim to acknowledge a report within **3 business days**
2. We may ask follow-up questions for clarification or reproduction
3. We aim to fix critical vulnerabilities within **30 days**
4. Coordinated disclosure will be managed on a case-by-case basis, normally by publishing a GitHub
   security advisory once a fixed release is available

We will not publicly discuss security issues until a fix or mitigation is available.

---

## What to _not_ do

Please do not:

- Open a public issue describing a vulnerability
- Share sensitive details publicly
- Attempt to exploit the vulnerability in production or in ways that compromise user data

Responsible disclosure helps protect all users of this project.

---

## Verifying the Container Image

Every release image published to `ghcr.io/fells-code/seamless-auth-api` (from v0.8.0) is signed
with cosign keyless signing from this repository's release workflow, and carries an SPDX SBOM and
a SLSA provenance statement. To check the signature before you run an image:

```bash
cosign verify ghcr.io/fells-code/seamless-auth-api:v0.19.1 \
  --certificate-identity-regexp '^https://github\.com/fells-code/seamless-auth-api/\.github/workflows/docker-publish\.yml@refs/(heads/main|tags/v.*)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

How to read the SBOM and provenance, and what each check proves, is in
[docs/production-operations.md](./docs/production-operations.md#verifying-the-container-image).

---

## Best Practices

Seamless Auth API uses modern identity and crypto best practices, but you should always:

- Review configuration and deployment settings carefully
- Rotate signing keys and the service token periodically
- Use HTTPS end to end in production
- Isolate your instance from untrusted networks
- Verify the signature of the container image you deploy

The API sets and reads no browser cookies. It is a bearer/JSON API meant to sit behind a trusted
server adapter, and cookie settings belong to that adapter.

Some behaviors are deliberate tradeoffs rather than oversights, including the residual user
enumeration on `/login`, ephemeral token replay within its TTL, and email and phone being stored
in plaintext. Each is stated with its reasoning and mitigating controls in
[docs/security-posture.md](./docs/security-posture.md). Please read it before reporting one of
those as a vulnerability.

---

Thank you for helping keep Seamless Auth API secure!
