# Public Sector

Requirements that reach this codebase from the public sector market: state,
county, city and K-12 agencies migrating off passwords onto phishing-resistant
authentication.

## What is and is not in this directory

Only [CERTIFICATION-READINESS.md](./CERTIFICATION-READINESS.md) is published
here. It is an engineering document: what the API and the SDKs must change to
earn FIDO Functional Certification and to score well on a GovRAMP Security
Snapshot.

The business and delivery documents it references (the operating plan, the
Maryland go to market, and the client migration runbook) are **not** in this
repository and are not published. They live in the private `fellscode`
repository under `docs/public-sector/`. Anything in this directory that cites
them is citing an internal document deliberately, and links to them will not
resolve here.

The split is intentional. This repository is public. Commercial strategy is not.

## What those documents imply for this repository

They contain open decisions that are product requirements here, not just
business positions. Pulled out so they are visible to anyone working in this
codebase, without needing access to the source documents:

- **Data residency.** No standing commitment yet. Whatever is decided
  constrains deployment topology and belongs in
  [configuration.md](../configuration.md).
- **CJIS position.** Determines whether criminal justice workloads can be
  served at all, and what that requires of the service. The reading from the
  code today is in Part C of the certification readiness document.
- **Synced passkey default.** The stated design position is blocked by default,
  agency may enable. **Confirmed not implemented.** See Part D, and
  [issue #170](https://github.com/fells-code/seamless-auth-api/issues/170).
- **PIV and smart card support level.** Currently unstated. Relevant to agencies
  that already issue cards.
- **Audit event retention.** Must map to state records retention schedules
  rather than a product default. See
  [admin-operations.md](../admin-operations.md) and
  [issue #173](https://github.com/fells-code/seamless-auth-api/issues/173).
- **Recovery flow.** The default is in-person identity-proofed recovery with a
  documented remote exception. The service cannot currently enforce or record
  that. See [issue #158](https://github.com/fells-code/seamless-auth-api/issues/158).
- **GovRAMP Security Snapshot findings.** Scored against 40 controls drawn from
  NIST SP 800-53 Rev. 5. Remediation lands in this codebase.

## Tracking

All of it is tracked in
[issue #155](https://github.com/fells-code/seamless-auth-api/issues/155),
broken into working sessions.

## Related

The public sector website design and its implementation spec live in the
private `fellscode` repository under `design/public-sector/`.
