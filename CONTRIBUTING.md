# Contributing to Seamless Auth Server

Thanks for your interest in contributing. This project powers passwordless authentication flows and is security-sensitive, so we value correctness, clarity, and careful changes over speed.

## Code of conduct

Be respectful, constructive, and professional. Harassment or abusive behavior is not tolerated.

## How to contribute

### 1) Report bugs

- Search existing issues first.
- If you found a security issue, **do not open a public issue**. Follow the Security section below.

When filing a bug, include:

- Expected behavior
- Actual behavior
- Reproduction steps
- Environment (OS, Node version, DB version, deployment mode)
- Logs (redact secrets)

### 2) Suggest features

Open an issue describing:

- The problem you are solving
- Why it matters
- Proposed API/UX
- Alternatives considered

### 3) Submit a pull request

1. Fork the repo
2. Create a branch: `feat/<short-name>` or `fix/<short-name>`
3. Keep PRs focused and small where possible
4. Add/adjust tests
5. Update docs (README or docs folder) if behavior changes
6. Open a PR with a clear description and checklist

## Development setup

### Requirements

- Node.js (LTS recommended)
- A Postgres instance (local, Docker, or managed)

### Install

- `npm install`

### Run (dev)

- `npm run dev`

### Tests

- `npm test`

### Lint / formatting

- `npm run lint`
- `npm run format`

## Coding standards

- Prefer small, composable modules
- Avoid introducing new dependencies unless necessary
- Validate inputs at API boundaries
- Never log secrets (tokens, cookie values, private keys, OTP codes)
- Treat auth and crypto changes as high-risk (add tests + docs)

## Security

### Reporting a vulnerability

Please report security issues privately.

- Email: security@seamlessauth.com
- Subject: `Security Issue: seamless-auth-server`

Include:

- Impact and severity assessment (if known)
- Reproduction steps or PoC
- Affected versions / commit hashes
- Suggested fix (if you have one)

We will acknowledge receipt and work with you on a responsible disclosure timeline.

## License / contribution terms

By contributing, you agree that your contributions will be licensed under the same license as this repository (AGPL-3.0-only), unless otherwise agreed in writing.

## Release process

Maintainers may squash-merge PRs and may edit titles/descriptions for clarity.
