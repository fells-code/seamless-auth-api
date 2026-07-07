# Contributing to Seamless Auth

Thank you for contributing to Seamless Auth.

## Philosophy

Seamless Auth is:

- Passwordless-first
- Security-focused
- Minimal and intentional
- Infrastructure-grade software

## Before You Start

For non-trivial changes:

1. Open an issue first
2. Explain the motivation
3. Describe your proposed solution
4. Wait for feedback

## Development Setup

### 1. Fork and Clone

Fork the repository and clone it locally:

```bash
# Clone the auth server code or your forks
git clone https://github.com/fells-code/seamless-auth-api.git
```

---

## 2. Run the Seamless Auth Server

```bash
cd seamless-auth-api
cp .env.example .env
```

### If docker and docker compose are avaliable

```bash
docker compose up -d
```

> If you are using docker you can stop here and move on to Step 3.

### If not using docker

Start postgres in whatever way your system does e.g. on mac

```bash
brew services start postgresql
```

### Prepare the database

```bash
npm install

npm run db:create
npm run db:migrate

npm run dev
```

---

Ensure the server is running locally (default: `http://localhost:5312`).

```bash
curl http://localhost:5312/health/status

## Expected result
## {"message":"System up"}
```

---

## Configuration

For a full reference of every environment variable and `system_config` key (which are
required, their defaults, and where each takes effect), see
[docs/configuration.md](./docs/configuration.md).

## Testing

The test suite runs on a mock database by default, so **no Postgres is required** for most work.

```bash
npm run test:run        # run the whole suite once (mock DB)
npm run coverage        # run with coverage thresholds
```

Run a single file or a directory while iterating:

```bash
npx vitest run tests/integration/otp/otp.spec.ts     # one file
npx vitest run tests/unit/utils                       # a directory
npx vitest tests/unit/utils/redaction.spec.ts         # watch mode
```

Only a few tests exercise real database behavior. To run those against a running Postgres:

```bash
TEST_DB=postgres npm run test:run
```

### Writing a test

Use the shared factories in [`tests/factories/`](./tests/factories) to build valid domain
objects instead of hand-rolling fixtures. For example:

```ts
import { buildUser } from '../../factories/userFactory.js';
import { buildSystemConfig } from '../../factories/systemConfigFactory.js';

const user = buildUser({ phone: null });
const config = buildSystemConfig({ login_methods: ['passkey'] });
```

Integration tests build the app with `createApp()` and drive it with `supertest`; see the
existing specs under `tests/integration/` for the pattern. Rate limiters and messaging are
mocked in `tests/setup/mocks.ts`, so you do not need to work around them.

## Expectations

When submitting a pull request:

- Ensure the SDK works against a running local auth server
- Verify login, logout, and session behavior
- Confirm role-based logic works as expected
- Run lint and tests before submitting

This ensures changes remain aligned with real authentication flows and infrastructure behavior.

### What a good PR includes

- **Scoped** to one change; unrelated cleanups go in their own PR.
- **Schemas + tests for new or changed routes.** Use the `schemas` option in the route
  definition (request + response) so validation and OpenAPI stay aligned, and add a test under
  `tests/`.
- **A changeset** for user-facing changes (`npm run changeset`). Do not hand-edit `CHANGELOG.md`
  or the version in `package.json`.
- **The AGPL license header** on every new `src/**/*.ts` file (eslint enforces this).
- **Conventional Commit** messages (see below); commitlint enforces this on commit.
- **Green checks**: `npm run typecheck`, `npm run lint`, and the test suite. The pre-commit hook
  runs these for you.
- For **contract changes** (routes, response/request schemas, token fields, status codes),
  call out the downstream impact on the SDKs in the PR description.

## Commit Conventions

- feat:
- fix:
- docs:
- refactor:
- test:
- chore:

Example:

feat: add configurable token expiration override

## Pull Requests Must

- Be scoped
- Include tests
- Update docs
- Pass CI
- Come from contributors who have starred the repository

## Star Requirement

We only accept pull requests from contributors who have starred this repository on GitHub.

This requirement is enforced automatically for pull requests opened against the public GitHub repository.

If you plan to open a pull request:

1. Visit the repository page on GitHub
2. Click `Star`
3. Open your pull request after the star is visible on your account

Pull requests that do not meet this requirement may be closed without review.

## Licensing

By contributing, you agree your contributions fall under the project license.
