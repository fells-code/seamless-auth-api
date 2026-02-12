# Seamless Auth API

**Seamless Auth API** is the open-source core authentication server for SeamlessAuth: an exclusively passwordless authentication system designed for modern web applications.

It provides the backend services for passkeys (WebAuthn) and other passwordless flows, issuing secure sessions and tokens while giving teams full transparency into how authentication is implemented.

> Looking for the managed experience (hosting, upgrades, dashboards, metrics, backups, SLAs)? See **https://seamlessauth.com** for managed services.

## Scope and Non-Goals

Seamless Auth API is the **open-source authentication engine** that powers SeamlessAuth. Its goal is to provide secure, auditable, and self-hostable passwordless authentication primitives.

This repository intentionally focuses on **authentication only**.

### What this repository includes

- Passwordless authentication flows (e.g. passkeys, OTP where configured)
- Secure session and token handling
- User registration and authentication APIs
- WebAuthn / Passkeys support
- JWKS and token verification endpoints
- Database models and migrations required for auth
- Local development and self-hosting support

Everything in this repository can be:

- Audited
- Modified
- Self-hosted
- Run without any SeamlessAuth-managed services

### What this repository does **not** include

The following are **intentionally out of scope** and are part of the managed SeamlessAuth service:

- Admin portal or dashboard UI
- Billing, subscriptions, or plan enforcement
- Tenant provisioning or lifecycle management
- Hosted metrics, analytics, or usage dashboards
- Managed secrets storage or key rotation services
- Automated upgrades, backups, or restore tooling
- Email or SMS services to service the OTP requests
- Support SLAs or operational monitoring

Self-hosted users are free to implement any of the above on their own, but they are not required to use SeamlessAuth Managed Service.

### About secrets and infrastructure

Seamless Auth API expects secrets to be provided by the environment or by a user-supplied secret store.

This repository does **not** assume any specific cloud provider, billing system, or control plane.

## Why Seamless Auth API

- Passwordless-first design (no passwords to steal)
- Modern session handling using secure, HTTP-only cookies
- WebAuthn / passkeys support
- Token and JWKS support for service-to-service auth
- Built for inspection, auditability, and self-hosting

This repository contains **only the auth server**. The admin portal, billing system, and hosted control plane are proprietary and offered as a managed service.

## Who this is for

- Teams that want to **self-host** authentication infrastructure
- Security-conscious organizations that require code transparency
- Developers evaluating SeamlessAuth internals before using the hosted offering

If you want hosted auth with a full control plane and operational support, use the managed service instead.

## High-level architecture

- Auth server (this repository)
- Postgres for persistence
- Your application integrates via:
  - SeamlessAuth server SDK (recommended)
  - Direct HTTP APIs (advanced)

---

## Local development quickstart

### Prerequisites

- Node.js (LTS recommended)
- Postgres (local, Docker, or managed)

### Configuration

Copy the `.env.example` to an `.env` file and populate empty values.

Never commit real secrets. Use `.env.example` for documentation.

### Install & run

```
npm install
npm run dev
```

The server should start on `http://localhost:5001` (or your configured port).

---

# Docker Quickstart (5 minutes)

This is the fastest way to run **Seamless Auth API** locally using Docker.

---

## Prerequisites

- Docker (Docker Desktop or Docker Engine)
- A running PostgreSQL instance (local or Docker)

---

## 1. Pull the public image

```bash
docker pull ghcr.io/fells-code/seamless-auth-api:latest
```

Available tags:

- `latest` – latest stable release
- `nightly` – latest build from `main`
- `vX.Y.Z` – specific versioned releases

---

## 2. Create an environment file

Copy the example and adjust as needed:

```bash
cp .env.example .env
```

At minimum, ensure these values are set:

```env
DB_HOST=localhost
DB_PORT=5432
DB_NAME=seamless_auth
DB_USER=myuser
DB_PASSWORD=mypassword
APP_ORIGIN=http://localhost:5001
ISSUER=http://localhost:5312
```

⚠️ Do not commit `.env` files. They are ignored by default.

---

## 3. Run PostgreSQL (example with Docker)

If you do not already have Postgres running:

```bash
docker run -d \
  --name seamless-auth-postgres \
  -e POSTGRES_USER=myuser \
  -e POSTGRES_PASSWORD=mypassword \
  -e POSTGRES_DB=seamless_auth \
  -p 5432:5432 \
  postgres:15
```

Update DB env values accordingly.

## 4. Run Seamless Auth Server

```bash
docker run --rm \
  --env-file .env \
  -p 5312:5312 \
  ghcr.io/fells-code/seamless-auth-api:latest
```

The server will:

- Validate required environment variables
- Start on port `5312`
- Expose health and authentication endpoints

## 5. Verify it is running

```bash
curl http://localhost:5312/health
```

You should receive a healthy response.

## Notes for self-hosting

- Secrets are provided via environment variables
- Keys are generated or mounted at runtime as needed
- This image contains only the open-source authentication server
- No admin portal, billing, or managed infrastructure is included

For production deployments:

- Use HTTPS
- Configure secure cookies
- Rotate signing keys
- Back up your database
- Monitor authentication failures

## Prefer not to self-host?

SeamlessAuth managed services provides a fully managed experience built on top of this same open-source core, including hosting, upgrades, dashboards, backups, and SLAs.

## Production notes

Authentication infrastructure is security-sensitive.

For production deployments:

- Use HTTPS end-to-end
- Enable secure cookies (`Secure`, correct `SameSite`)
- Restrict CORS origins
- Rotate signing keys and secrets regularly
- Enable database backups and test restores
- Monitor auth failures and suspicious behavior

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Security

**Do not open public issues for security vulnerabilities.**

Email: security@seamlessauth.com  
Include reproduction steps, affected versions, and impact if known.

## License

Licensed under **GNU Affero General Public License v3.0 (AGPL-3.0-only)**.

If you want to embed Seamless Auth Server into a proprietary product or offer it as a managed service without AGPL obligations, commercial licenses may be available.

Contact: support@seamlessauth.com
