import { beforeEach, describe, expect, it, vi } from 'vitest';

import { requireDeviceSessionStepUp } from '../../../src/middleware/requireDeviceSessionStepUp';

describe('requireDeviceSessionStepUp', () => {
  let res: any;
  let next: any;

  beforeEach(() => {
    res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
    next = vi.fn();
  });

  it('passes every session that is not from a device grant', () => {
    requireDeviceSessionStepUp({} as never, res, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('refuses a session from a device grant with no step-up', () => {
    const req = { deviceChildSession: { stepUpVerifiedAt: null, stepUpMethod: null } };

    requireDeviceSessionStepUp(req as never, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: 'step_up_required', fresh: false, method: null }),
    );
  });

  it('refuses a stale step-up', () => {
    const req = {
      deviceChildSession: {
        stepUpVerifiedAt: new Date(Date.now() - 6 * 60_000),
        stepUpMethod: 'totp',
      },
    };

    requireDeviceSessionStepUp(req as never, res, next);

    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: 'step_up_required', fresh: false, method: 'totp' }),
    );
  });

  it('passes a fresh step-up', () => {
    const req = { deviceChildSession: { stepUpVerifiedAt: new Date(), stepUpMethod: 'totp' } };

    requireDeviceSessionStepUp(req as never, res, next);

    expect(next).toHaveBeenCalled();
  });
});
