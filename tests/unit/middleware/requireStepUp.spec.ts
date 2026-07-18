import { describe, expect, it, vi } from 'vitest';

import { requireStepUp } from '../../../src/middleware/requireStepUp.js';
import { Session } from '../../../src/models/sessions.js';
import { buildSession } from '../../factories/sessionFactory.js';

function buildReq(overrides: Record<string, unknown> = {}) {
  return {
    user: { id: 'user-1' },
    sessionId: 'session-1',
    ...overrides,
  } as any;
}

function buildRes() {
  const res: any = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  return res;
}

describe('requireStepUp', () => {
  it('calls next when the current session has fresh step-up verification', async () => {
    (Session.findOne as any).mockResolvedValue(
      buildSession({
        stepUpVerifiedAt: new Date(),
        stepUpMethod: 'webauthn',
      }),
    );

    const req = buildReq();
    const res = buildRes();
    const next = vi.fn();

    await requireStepUp()(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('returns 401 when the request has no authenticated user or session', async () => {
    const res = buildRes();
    const next = vi.fn();

    await requireStepUp()(buildReq({ user: undefined, sessionId: undefined }), res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'unauthorized' });
  });

  it('returns 401 when the current session cannot be found', async () => {
    (Session.findOne as any).mockResolvedValue(null);

    const res = buildRes();
    const next = vi.fn();

    await requireStepUp()(buildReq(), res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'unauthorized' });
  });

  it('returns step_up_required when step-up verification is stale', async () => {
    (Session.findOne as any).mockResolvedValue(
      buildSession({
        stepUpVerifiedAt: new Date(Date.now() - 10 * 60 * 1000),
        stepUpMethod: 'webauthn',
      }),
    );

    const req = buildReq();
    const res = buildRes();
    const next = vi.fn();

    await requireStepUp()(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: 'step_up_required',
        fresh: false,
      }),
    );
  });
});
