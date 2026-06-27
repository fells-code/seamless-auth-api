# CLAUDE.md

This file is loaded automatically at the start of every Claude Code session.

The full architecture guide lives in **[AGENTS.md](AGENTS.md)** — imported below so
there is a single source of truth. Read it for the runtime shape, folder map, token
model, and config layers.

@AGENTS.md

## Working agreement

### Verify before declaring done

This project has a fast, reliable check loop. Run the relevant ones after changes and
report real output — never claim a change works without running them.

| Check    | Command             | Notes                                                           |
| -------- | ------------------- | --------------------------------------------------------------- |
| Types    | `npm run typecheck` | `tsc --noEmit`, ~2s                                             |
| Lint     | `npm run lint`      | eslint, ~2s. Enforces license headers + import sort             |
| Tests    | `npm run test:run`  | vitest, ~2s. **Uses a mock DB by default — no Postgres needed** |
| Coverage | `npm run coverage`  | thresholds: lines/functions/statements 70%, branches 65%        |

Tests default to `TEST_DB=mock`. Only set `TEST_DB=postgres` (with a running Postgres)
when specifically exercising real DB behavior.

### Conventions enforced by tooling

- **License header** — every `src/**/*.ts` file must begin with the AGPL header (eslint
  `license-header/header` errors otherwise). Copy it from any existing file, e.g.
  [src/utils/otp.ts](src/utils/otp.ts):

  ```ts
  /*
   * Copyright © 2026 Fells Code, LLC
   * Licensed under the GNU Affero General Public License v3.0
   * See LICENSE file in the project root for full license information
   */
  ```

- **Commits** — Conventional Commits, enforced by commitlint + husky on commit
  (`feat:`, `fix:`, `chore:`, `docs:`, `ci:`, …). Husky also runs lint-staged.
- **Releases** — managed by Changesets. User-facing changes need a changeset
  (`npm run changeset`); don't hand-edit `CHANGELOG.md` or the version in `package.json`.
- **No `any`** (`@typescript-eslint/no-explicit-any` is an error) and imports/exports are
  auto-sorted (`simple-import-sort`).

### Codebase shape (where to make changes)

Routes are auto-discovered: each `src/routes/*.routes.ts` registers handlers via
`defineRoute`, which also wires OpenAPI metadata and validates request/response against
Zod schemas in `src/schemas/`. Trace behavior **route → controller → service → model**.
A new endpoint usually touches: a `*.routes.ts`, a controller, request/response schemas,
and a test under `tests/`.

### Don't touch

- `keys/` and `.env*` — local secrets / signing keys. Never read, commit, or modify them.
- `dist/` and `coverage/` — generated output.

### Security posture

This is an authentication server. Treat auth, token, OTP, session, and crypto code as
high-stakes: prefer constant-time comparisons, hash secrets at rest, fail closed, and run
`/security-review` on changes to those paths before considering them done.
