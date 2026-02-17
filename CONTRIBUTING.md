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

## Expectations

When submitting a pull request:

- Ensure the SDK works against a running local auth server
- Verify login, logout, and session behavior
- Confirm role-based logic works as expected
- Run lint and tests before submitting

This ensures changes remain aligned with real authentication flows and infrastructure behavior.

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
