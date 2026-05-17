import { describe, expect, it, vi } from 'vitest';

import { Session } from '../../../src/models/sessions.js';
import {
  DEFAULT_STEP_UP_MAX_AGE_SECONDS,
  getSessionStepUpStatus,
  getStepUpStatusFromSession,
  recordStepUpVerification,
} from '../../../src/services/stepUpService.js';
import { buildSession } from '../../factories/sessionFactory.js';

describe('stepUpService', () => {
  it('marks sessions without step-up as not fresh', () => {
    const status = getStepUpStatusFromSession(
      buildSession({ stepUpVerifiedAt: null, stepUpMethod: null }),
    );

    expect(status.sessionFound).toBe(true);
    expect(status.fresh).toBe(false);
    expect(status.verifiedAt).toBeNull();
    expect(status.expiresAt).toBeNull();
  });

  it('marks recent step-up as fresh', () => {
    const verifiedAt = new Date('2026-05-15T12:00:00.000Z');
    const status = getStepUpStatusFromSession(
      buildSession({ stepUpVerifiedAt: verifiedAt, stepUpMethod: 'webauthn' }),
      DEFAULT_STEP_UP_MAX_AGE_SECONDS,
      new Date('2026-05-15T12:02:00.000Z'),
    );

    expect(status.fresh).toBe(true);
    expect(status.method).toBe('webauthn');
    expect(status.expiresAt?.toISOString()).toBe('2026-05-15T12:05:00.000Z');
  });

  it('marks expired step-up as stale', () => {
    const verifiedAt = new Date('2026-05-15T12:00:00.000Z');
    const status = getStepUpStatusFromSession(
      buildSession({ stepUpVerifiedAt: verifiedAt, stepUpMethod: 'webauthn' }),
      DEFAULT_STEP_UP_MAX_AGE_SECONDS,
      new Date('2026-05-15T12:06:00.000Z'),
    );

    expect(status.fresh).toBe(false);
  });

  it('records step-up verification on the current session', async () => {
    const session = buildSession({ stepUpVerifiedAt: null, stepUpMethod: null });
    (Session.findOne as any).mockResolvedValue(session);

    const verifiedAt = new Date('2026-05-15T12:00:00.000Z');
    const status = await recordStepUpVerification({
      sessionId: 'session-1',
      userId: 'user-1',
      method: 'webauthn',
      verifiedAt,
    });

    expect(Session.findOne).toHaveBeenCalledWith({
      where: {
        id: 'session-1',
        userId: 'user-1',
        revokedAt: null,
      },
    });
    expect(session.stepUpVerifiedAt).toBe(verifiedAt);
    expect(session.stepUpMethod).toBe('webauthn');
    expect(session.save).toHaveBeenCalled();
    expect(status?.fresh).toBe(true);
  });

  it('returns a missing status when the current session is not found', async () => {
    (Session.findOne as any).mockResolvedValue(null);

    const status = await getSessionStepUpStatus({
      sessionId: 'missing-session',
      userId: 'user-1',
    });

    expect(status.sessionFound).toBe(false);
    expect(status.fresh).toBe(false);
  });
});
