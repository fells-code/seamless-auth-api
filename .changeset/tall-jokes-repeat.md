---
'seamless-auth-api': patch
---

Stop the test suite failing on assertions unrelated to the change under test.

`vi.clearAllMocks()` in each spec's `beforeEach` empties call history but leaves
the `mockResolvedValueOnce` queue intact, so a value queued by one test and never
consumed was returned to a later, unrelated one. That shifted every subsequent
queued value by a place, surfacing as a wrong status, a wrong body, or a request
that never settled and timed out. Vitest now resets mocks between tests, which is
what drains the queue.

`vi.stubEnv` and `vi.stubGlobal` write to the process rather than the module
registry, and `isolate` does not roll those back between files, so a stubbed
`NODE_ENV` or a stubbed global `fetch` outlived the file that set it. Both are
now restored automatically. `APP_ORIGINS` moved from a stub in `mocks.ts` to a
plain assignment in `env.ts`, since restoring stubs before every test would
otherwise drop it after the first test of each file.

Route handlers answer the request before their fire-and-forget audit logging
settles, so supertest resolved with continuations still queued and a stray call
could land in the middle of the next test, breaking a `toHaveBeenCalledTimes` or
a `toHaveBeenNthCalledWith` on a shared mock. Those are now drained after every
test.

With the leaks closed, spec files no longer have to run one at a time:
`fileParallelism` is back on and the suite runs in about a sixth of the time.
`npm run coverage` no longer forces sequential execution either.
