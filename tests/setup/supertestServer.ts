import type { Server } from 'http';
import { afterAll, vi } from 'vitest';

/**
 * Gives each spec file one listening server instead of one per request.
 *
 * supertest builds a fresh `http.Server` for every call, listens on an ephemeral
 * port, and closes it again in the response callback
 * (`supertest/lib/test.js`). Across the suite that is roughly 440
 * create/listen/connect/close cycles per run, spread over the worker pool, and
 * occasionally one request is lost inside that cycle: the client connects, no
 * server ever emits `request`, and neither side errors. The test then sits until
 * the 20 second timeout. Traced in #214, where a failing run showed 439 requests
 * sent against 438 served, and 439 binds against 438 closes.
 *
 * Handing supertest a server that is already listening skips that entirely. It
 * only calls `listen` when `address()` is empty, and only closes a server it
 * opened itself, so one server per app survives the whole file.
 *
 * Done here rather than in each spec because the alternative is threading a
 * server through roughly 350 call sites.
 */
const { servers } = vi.hoisted(() => ({ servers: new Map<unknown, Server>() }));

vi.mock('supertest', async (importOriginal) => {
  const actual = await importOriginal<typeof import('supertest')>();

  const withSharedServer = (app: unknown, options?: unknown) => {
    // Anything that is not an app to be mounted (a URL string, or a server a spec
    // opened itself) is supertest's business, not ours.
    if (typeof app !== 'function') {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return (actual.default as any)(app, options);
    }

    let server = servers.get(app);

    if (!server) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      server = (app as any).listen(0) as Server;
      servers.set(app, server);
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (actual.default as any)(server, options);
  };

  // Carry over `agent`, `Test` and `cookies`, which hang off the default export.
  // Note that `request.agent(app)` opens its own server and so opts out of the
  // sharing above. No spec uses it today; one that starts to would be back on the
  // per-request path.
  Object.assign(withSharedServer, actual.default);

  return { ...actual, default: withSharedServer };
});

afterAll(() => {
  for (const server of servers.values()) {
    server.close();
  }

  servers.clear();
});
