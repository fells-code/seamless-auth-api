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

### If docker and docker compose are avaliable

```bash
cd seamless-auth-api
docker compose -f docker-compose.dev.yml up
```

That builds the API from source, generates development signing keys, runs migrations (creating
the database on first boot), and starts a watcher that reloads on change. No `.env` file is
needed: the compose file supplies development defaults. If you do create one, its values win, so
you can point at a real messaging transport or OAuth provider without editing the compose file.

To run the project rather than work on it, use `docker compose up` instead. That uses the
published image and also serves the admin console at `/console`, which the dev stack does not
bundle. See the Docker Quickstart in [README.md](./README.md).

> If you are using docker you can stop here and move on to Step 3.

### If not using docker

```bash
cd seamless-auth-api
cp .env.example .env
```

Start postgres in whatever way your system does e.g. on mac

```bash
brew services start postgresql
```

### Prepare the database

```bash
npm install

npm run db:create
npm run migrate:up

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
  `tests/`. Run `npm run generate:api` and commit `openapi.json` plus `src/generated/api.ts`;
  a test fails when they drift from the routes.
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

## Licensing

By contributing, you agree your contributions fall under the project license.
