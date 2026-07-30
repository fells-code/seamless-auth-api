---
'seamless-auth-api': patch
---

Prune unused dependencies and clear the fixable audit findings.

Removed three declared dependencies that nothing in the repo imports: `@sequelize/postgres`
(an alpha of the Sequelize v7 rewrite, which sat in `dependencies` next to `sequelize@6` and
shipped to the runtime image), `@types/bcrypt` (the code uses `bcrypt-ts`, which carries its own
types, and a types package does not belong in production dependencies), and `ts-node` (everything
runs through `tsx`). The production dependency tree drops by 38 packages.

`tsx` moves to `^4.23.1`, which takes `esbuild ~0.28.0` and so resolves the patched `esbuild`
0.28.1, and the `allowScripts` pin follows it. Together with `npm audit fix`, this clears the
`esbuild`, `fast-uri`, `js-yaml`, `tar`, and nested `minimatch` advisories.

`@types/node` moves to `^24.10.1` to match the `>=24 <25` engine and the pinned Node 24 runtime,
and `@eslint/js` moves to `^10.0.1` to line up with the already-installed ESLint 10. The ESLint 10
recommended set adds `preserve-caught-error`, which the log-and-rethrow sites in `src/lib/token.ts`
and `src/utils/otp.ts` already satisfy, so enabling it needs no further source changes.

Two advisories are knowingly left in place because neither has a non-breaking fix. `sequelize-cli`
6.6.5 (the latest) still depends on `js-beautify`, which reaches a vulnerable `brace-expansion`;
pinning `brace-expansion` to the patched 5.0.8 is not viable because its CJS entry exports
`{ expand }` while the `minimatch@9` in that chain calls the default export, which would break
migrations at container start. `sequelize@6` pins `uuid ^8`, and the `uuid` advisory covers only
`v3`/`v5`/`v6` with a `buf` argument while Sequelize uses `v1` and `v4`, so it is not reachable.
