import { vi } from 'vitest';

vi.mock('http', () => {
  return {
    default: {
      get: vi.fn(),
    },
  };
});

const exitSpy = vi.spyOn(process, 'exit').mockImplementation(() => {
  throw new Error('process.exit'); // prevent actual exit
});

import { describe, it, expect, beforeEach } from 'vitest';

describe('health check script', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  it('exits 0 on 200 response', async () => {
    const http = await import('http');

    const exitSpy = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit');
    });

    // @ts-ignore
    (http.default.get as any).mockImplementation((_url, cb) => {
      cb({ statusCode: 200 });
      return { on: vi.fn() };
    });

    try {
      await import('../../../src/healthCheck');
    } catch {}

    expect(exitSpy).toHaveBeenCalledWith(0);
  });

  it('exits 1 on non-200 response', async () => {
    const http = await import('http');

    const exitSpy = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit');
    });

    // @ts-ignore
    (http.default.get as any).mockImplementation((_url, cb) => {
      cb({ statusCode: 500 });
      return { on: vi.fn() };
    });

    try {
      await import('../../../src/healthCheck');
    } catch {}

    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it('exits 1 on request error', async () => {
    const http = await import('http');

    const exitSpy = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit');
    });

    const onMock = vi.fn((event, handler) => {
      if (event === 'error') handler();
    });

    (http.default.get as any).mockReturnValue({
      on: onMock,
    });

    try {
      await import('../../../src/healthCheck');
    } catch {}

    expect(exitSpy).toHaveBeenCalledWith(1);
  });
});
