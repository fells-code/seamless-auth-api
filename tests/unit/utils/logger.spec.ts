import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const existsSync = vi.fn();
const mkdirSync = vi.fn();

vi.mock('fs', () => ({
  default: { existsSync, mkdirSync },
  existsSync,
  mkdirSync,
}));

let printfCallback: ((info: Record<string, unknown>) => string) | undefined;
const consoleTransport = vi.fn();
const fileTransport = vi.fn();
const createLogger = vi.fn(() => ({ info: vi.fn() }));

vi.mock('winston', () => ({
  createLogger,
  format: {
    combine: (...args: unknown[]) => args,
    timestamp: () => 'ts',
    printf: (cb: (info: Record<string, unknown>) => string) => {
      printfCallback = cb;
      return cb;
    },
  },
  transports: {
    Console: consoleTransport,
    File: fileTransport,
  },
  Logger: class {},
}));

const originalNodeEnv = process.env.NODE_ENV;

describe('getLogger', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    printfCallback = undefined;
  });

  afterEach(() => {
    process.env.NODE_ENV = originalNodeEnv;
  });

  it('creates the log directory and a file transport in dev when the directory is missing', async () => {
    process.env.NODE_ENV = 'development';
    existsSync.mockReturnValue(false);

    const getLogger = (await import('../../../src/utils/logger.js')).default;
    getLogger('mod-missing-dir');

    expect(mkdirSync).toHaveBeenCalledWith(expect.stringContaining('logs'), { recursive: true });
    expect(fileTransport).toHaveBeenCalledTimes(1);
    expect(consoleTransport).toHaveBeenCalledTimes(1);
    expect(createLogger).toHaveBeenCalledTimes(1);
  });

  it('does not recreate the log directory when it already exists', async () => {
    process.env.NODE_ENV = 'development';
    existsSync.mockReturnValue(true);

    const getLogger = (await import('../../../src/utils/logger.js')).default;
    getLogger('mod-existing-dir');

    expect(mkdirSync).not.toHaveBeenCalled();
    expect(fileTransport).toHaveBeenCalledTimes(1);
  });

  it('omits the file transport in production', async () => {
    process.env.NODE_ENV = 'production';

    const getLogger = (await import('../../../src/utils/logger.js')).default;
    getLogger('mod-prod');

    expect(mkdirSync).not.toHaveBeenCalled();
    expect(fileTransport).not.toHaveBeenCalled();
    expect(consoleTransport).toHaveBeenCalledTimes(1);
  });

  it('falls back to the development log level when NODE_ENV is unset', async () => {
    delete process.env.NODE_ENV;
    existsSync.mockReturnValue(true);

    const getLogger = (await import('../../../src/utils/logger.js')).default;

    expect(getLogger('mod-no-env')).toBeDefined();
  });

  it('caches loggers per module name', async () => {
    process.env.NODE_ENV = 'development';
    existsSync.mockReturnValue(true);

    const getLogger = (await import('../../../src/utils/logger.js')).default;
    const first = getLogger('mod-cache');
    const second = getLogger('mod-cache');

    expect(first).toBe(second);
    expect(createLogger).toHaveBeenCalledTimes(1);
  });

  it('renders and redacts both string and non-string messages', async () => {
    process.env.NODE_ENV = 'development';
    existsSync.mockReturnValue(true);

    const getLogger = (await import('../../../src/utils/logger.js')).default;
    getLogger('mod-format');

    expect(printfCallback).toBeDefined();

    const stringLine = printfCallback!({
      level: 'info',
      message: 'token=supersecret',
      timestamp: 'T',
    });
    expect(stringLine).toContain('[mod-format]');
    expect(stringLine).toContain('INFO');
    expect(stringLine).toContain('token=[REDACTED]');

    const numericLine = printfCallback!({ level: 'warn', message: 42, timestamp: 'T' });
    expect(numericLine).toContain('WARN');
    expect(numericLine).toContain('42');
  });
});
