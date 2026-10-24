import { Application } from 'express';
import request from 'supertest';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const issueSessionAndRespondMock = vi.fn(async ({ res }) => {
  res.status(200).json({ message: 'Success', recovery: true, nextStep: 'enroll_passkey' });
});

vi.mock('../../../src/services/sessionIssuance.js', () => ({
  issueSessionAndRespond: issueSessionAndRespondMock,
}));

let decoy = false;
let attemptId = 'attempt-1';
let principal: Record<string, unknown>;

vi.mock('../../../src/middleware/attachAuthMiddleware.js', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../../../src/middleware/attachAuthMiddleware.js')>();

  return {
    ...actual,
    attachAuthMiddleware: () => (req: any, _res: any, next: any) => {
      req.user = principal;
      req.attemptId = attemptId;
      if (decoy) req.decoy = true;
      next();
    },
  };
});

import { createApp } from '../../../src/app.js';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { Session } from '../../../src/models/sessions.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import { DeliveryError } from '../../../src/services/deliveryError.js';
import {
  sendNoticeEmail,
  sendNoticeSms,
  sendOTPEmail,
  sendOTPSMS,
} from '../../../src/services/messagingService.js';
import { decoyPrincipalForSubject, decoySubjectFor } from '../../../src/services/decoyPrincipal.js';
import { installAccountRecoveryStore } from '../../factories/accountRecoveryStore.js';
import { mintInternalServiceToken } from '../../factories/serviceTokenFactory.js';
import { buildSystemConfig } from '../../factories/systemConfigFactory.js';

const HOUR_MS = 3600 * 1000;
let app: Application;
let rows: ReturnType<typeof installAccountRecoveryStore>;

function realUser(overrides: Record<string, unknown> = {}) {
  return {
    id: 'user-1',
    email: 'owner@example.com',
    phone: '+14155552671',
    emailVerified: true,
    phoneVerified: true,
    roles: ['user'],
    ...overrides,
  };
}

function enabled(overrides: Record<string, unknown> = {}) {
  (getSystemConfig as any).mockResolvedValue(
    buildSystemConfig({
      account_recovery: { enabled: true, delay: '1h' },
      frontend_url: 'https://app.example.com/',
      ...overrides,
    }),
  );
}

function sentCode() {
  const email = (sendOTPEmail as any).mock.calls.at(-1);
  if (email) return email[1] as string;
  return String((sendOTPSMS as any).mock.calls.at(-1)[1]);
}

async function startAndVerify(channel: 'email' | 'phone' = 'email') {
  await request(app).post('/recovery/start').send({ channel });
  return request(app).post('/recovery/verify').send({ code: sentCode() });
}

function afterDelay() {
  vi.useFakeTimers({ now: Date.now() + HOUR_MS + 1, toFake: ['Date'] });
}

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  decoy = false;
  attemptId = 'attempt-1';
  principal = realUser();
  rows = installAccountRecoveryStore();
  (Session.update as any).mockResolvedValue([2]);
  enabled();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('while account recovery is disabled', () => {
  it.each([
    ['post', '/recovery/start', { channel: 'email' }],
    ['post', '/recovery/verify', { code: '123456' }],
    ['get', '/recovery/status', undefined],
    ['post', '/recovery/complete', undefined],
  ] as const)('refuses %s %s, for a real account and a decoy alike', async (method, path, body) => {
    (getSystemConfig as any).mockResolvedValue(buildSystemConfig());

    for (const asDecoy of [false, true]) {
      decoy = asDecoy;
      const res = await request(app)[method](path).send(body);

      expect(res.status).toBe(403);
      expect(res.body).toEqual({ error: 'account_recovery_disabled' });
    }
  });
});

describe('in phishing-resistant-only mode', () => {
  it('refuses to start recovery, since it proves only an address', async () => {
    (getSystemConfig as any).mockResolvedValue(
      buildSystemConfig({
        account_recovery: { enabled: true, delay: '1h' },
        phishing_resistant_only: true,
      }),
    );

    for (const asDecoy of [false, true]) {
      decoy = asDecoy;
      const res = await request(app).post('/recovery/start').send({ channel: 'email' });

      expect(res.status).toBe(403);
      expect(res.body).toEqual({ error: 'account_recovery_disabled' });
    }
  });

  it('is reported unavailable to sign-in screens', async () => {
    (getSystemConfig as any).mockResolvedValue(
      buildSystemConfig({
        account_recovery: { enabled: true, delay: '1h' },
        phishing_resistant_only: true,
      }),
    );

    const res = await request(app).get('/system-config/public');

    expect(res.body.accountRecovery).toBe(false);
  });
});

describe('POST /recovery/start', () => {
  it('sends a code to the verified address on the channel', async () => {
    const res = await request(app).post('/recovery/start').send({ channel: 'phone' });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ message: expect.any(String) });
    expect(sendOTPSMS).toHaveBeenCalledWith('+14155552671', expect.any(Number));
    expect(rows).toHaveLength(1);
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'account_recovery_started' }),
    );
  });

  it('defaults to email', async () => {
    await request(app).post('/recovery/start').send({});

    expect(sendOTPEmail).toHaveBeenCalledWith(
      'owner@example.com',
      expect.stringMatching(/^\d{6}$/),
    );
  });

  it('answers the same for a channel the account has no verified address on', async () => {
    const real = await request(app).post('/recovery/start').send({ channel: 'email' });
    principal = realUser({ phone: null, phoneVerified: false });
    const missing = await request(app).post('/recovery/start').send({ channel: 'phone' });
    principal = realUser({ emailVerified: false });
    const unverified = await request(app).post('/recovery/start').send({ channel: 'email' });

    expect(missing.status).toBe(real.status);
    expect(missing.body).toEqual(real.body);
    expect(unverified.body).toEqual(real.body);
    expect(sendOTPSMS).not.toHaveBeenCalled();
    expect(sendOTPEmail).toHaveBeenCalledTimes(1);
  });

  it('refuses an unknown channel at validation', async () => {
    const res = await request(app).post('/recovery/start').send({ channel: 'carrier-pigeon' });

    expect(res.status).toBe(400);
  });

  it('hands the code to a credentialed caller that owns delivery instead of sending it', async () => {
    const res = await request(app)
      .post('/recovery/start')
      .set('x-seamless-auth-delivery-mode', 'external')
      .set('x-seamless-service-token', await mintInternalServiceToken())
      .send({ channel: 'email' });

    expect(res.status).toBe(200);
    expect(res.body.delivery).toEqual({
      kind: 'otp_email',
      to: 'owner@example.com',
      token: expect.stringMatching(/^\d{6}$/),
    });
    expect(sendOTPEmail).not.toHaveBeenCalled();
  });

  it('hands over an SMS code the same way', async () => {
    const res = await request(app)
      .post('/recovery/start')
      .set('x-seamless-auth-delivery-mode', 'external')
      .set('x-seamless-service-token', await mintInternalServiceToken())
      .send({ channel: 'phone' });

    expect(res.body.delivery).toMatchObject({ kind: 'otp_sms', to: '+14155552671' });
  });

  it('answers 500 when the code cannot be delivered', async () => {
    (sendOTPEmail as any).mockRejectedValueOnce(new DeliveryError('down', new Error('down')));

    const res = await request(app).post('/recovery/start').send({ channel: 'email' });

    expect(res.status).toBe(500);
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'account_recovery_failed' }),
    );
  });

  it('ignores an existing lockout, which is what recovery is for', async () => {
    const { AuthFailure } = await import('../../../src/models/authFailures.js');
    (AuthFailure.count as any).mockResolvedValue(1000);

    const res = await request(app).post('/recovery/start').send({ channel: 'email' });

    expect(res.status).toBe(200);
    expect(sendOTPEmail).toHaveBeenCalled();
  });
});

describe('POST /recovery/verify', () => {
  it('opens the request and notifies both verified addresses with a cancel link', async () => {
    const res = await startAndVerify('email');

    expect(res.status).toBe(200);
    expect(res.body.state).toBe('pending');
    expect(Date.parse(res.body.completesAt) - Date.parse(res.body.requestedAt)).toBe(HOUR_MS);

    const [to, , text] = (sendNoticeEmail as any).mock.calls[0];
    expect(to).toBe('owner@example.com');
    expect(text).toMatch(/https:\/\/app\.example\.com\/recovery\/cancel#\S+/);
    expect(text).toContain(res.body.completesAt);
    expect(sendNoticeSms).toHaveBeenCalledWith('+14155552671', expect.stringContaining('#'));
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'account_recovery_verified',
        metadata: expect.objectContaining({
          notices: [
            { channel: 'email', status: 'sent' },
            { channel: 'phone', status: 'sent' },
          ],
        }),
      }),
    );
  });

  it('records the notices as not sent when a credentialed caller owns delivery', async () => {
    const token = await mintInternalServiceToken();
    const started = await request(app)
      .post('/recovery/start')
      .set('x-seamless-auth-delivery-mode', 'external')
      .set('x-seamless-service-token', token)
      .send({ channel: 'email' });

    const res = await request(app)
      .post('/recovery/verify')
      .set('x-seamless-auth-delivery-mode', 'external')
      .set('x-seamless-service-token', token)
      .send({ code: started.body.delivery.token });

    expect(res.status).toBe(200);
    expect(sendNoticeEmail).not.toHaveBeenCalled();
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'account_recovery_verified',
        metadata: expect.objectContaining({
          notices: [
            { channel: 'email', status: 'not_sent_external_delivery' },
            { channel: 'phone', status: 'not_sent_external_delivery' },
          ],
        }),
      }),
    );
  });

  it('does not let a stranger suppress the notices with the delivery header alone', async () => {
    await request(app).post('/recovery/start').send({ channel: 'email' });

    const res = await request(app)
      .post('/recovery/verify')
      .set('x-seamless-auth-delivery-mode', 'external')
      .send({ code: sentCode() });

    expect(res.status).toBe(200);
    expect(sendNoticeEmail).toHaveBeenCalled();
    expect(sendNoticeSms).toHaveBeenCalled();
  });

  it('refuses a wrong code, and voids the request after five', async () => {
    await request(app).post('/recovery/start').send({ channel: 'email' });
    const code = sentCode();
    const other = code === '123456' ? '654321' : '123456';

    for (let i = 0; i < 5; i += 1) {
      const res = await request(app).post('/recovery/verify').send({ code: other });
      expect(res.status).toBe(401);
      expect(res.body).toEqual({ error: 'invalid_recovery_code' });
    }

    const res = await request(app).post('/recovery/verify').send({ code });

    expect(res.status).toBe(401);
    expect(rows[0].state).toBe('void');
    expect(sendNoticeEmail).not.toHaveBeenCalled();
  });

  it('resumes an open request on a new attempt without notifying again', async () => {
    const opened = await startAndVerify('email');
    vi.clearAllMocks();
    attemptId = 'attempt-2';

    const resumed = await startAndVerify('email');

    expect(resumed.status).toBe(200);
    expect(resumed.body.completesAt).toBe(opened.body.completesAt);
    expect(sendNoticeEmail).not.toHaveBeenCalled();
  });
});

describe('GET /recovery/status', () => {
  it('is pending until the delay passes, then ready', async () => {
    await startAndVerify();

    expect((await request(app).get('/recovery/status')).body.state).toBe('pending');

    afterDelay();

    expect((await request(app).get('/recovery/status')).body.state).toBe('ready');
  });

  it('answers 404 for an attempt that opened no request', async () => {
    await startAndVerify();
    attemptId = 'attempt-2';

    const res = await request(app).get('/recovery/status');

    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: 'recovery_not_found' });
  });
});

describe('POST /recovery/complete', () => {
  it('is refused until the delay has passed', async () => {
    await startAndVerify();

    const res = await request(app).post('/recovery/complete');

    expect(res.status).toBe(409);
    expect(res.body.error).toBe('recovery_not_ready');
    expect(Session.update).not.toHaveBeenCalled();
    expect(issueSessionAndRespondMock).not.toHaveBeenCalled();
  });

  it('revokes every session, notifies, and issues a recovery session once ready', async () => {
    await startAndVerify();
    vi.mocked(sendNoticeEmail).mockClear();
    afterDelay();

    const res = await request(app).post('/recovery/complete');

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ recovery: true, nextStep: 'enroll_passkey' });
    expect(Session.update).toHaveBeenCalledWith(
      expect.objectContaining({ revokedReason: 'account_recovery' }),
      { where: { userId: 'user-1', revokedAt: null } },
    );
    expect(issueSessionAndRespondMock).toHaveBeenCalledWith(
      expect.objectContaining({ method: 'account_recovery', recovery: true }),
    );
    expect(sendNoticeEmail).toHaveBeenCalledWith(
      'owner@example.com',
      expect.stringContaining('recovered'),
      expect.any(String),
    );
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'account_recovery_completed',
        metadata: expect.objectContaining({ revokedSessions: 2 }),
      }),
    );
    expect((await request(app).get('/recovery/status')).body.state).toBe('completed');
    expect((await request(app).post('/recovery/complete')).status).toBe(404);
  });

  it('answers 404 for an attempt that opened no request', async () => {
    const res = await request(app).post('/recovery/complete');

    expect(res.status).toBe(404);
  });
});

describe('POST /recovery/cancel', () => {
  function cancelTokenFromNotice() {
    const text = (sendNoticeEmail as any).mock.calls[0][2] as string;
    return text.match(/#(\S+)/)![1];
  }

  it('cancels the open request from the link in the notice', async () => {
    await startAndVerify();

    const res = await request(app)
      .post('/recovery/cancel')
      .send({ cancelToken: cancelTokenFromNotice() });

    expect(res.status).toBe(200);
    expect(rows[0].state).toBe('cancelled');
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'account_recovery_cancelled', userId: 'user-1' }),
    );

    expect((await request(app).get('/recovery/status')).body.state).toBe('cancelled');
    afterDelay();
    expect((await request(app).post('/recovery/complete')).status).toBe(404);
  });

  it('still cancels after recovery is switched off or phishing-resistant-only is turned on', async () => {
    await startAndVerify();
    enabled({ phishing_resistant_only: true });

    const res = await request(app)
      .post('/recovery/cancel')
      .send({ cancelToken: cancelTokenFromNotice() });

    expect(res.status).toBe(200);
    expect(rows[0].state).toBe('cancelled');
  });

  it('answers the same whether or not the token matched', async () => {
    await startAndVerify();
    const token = cancelTokenFromNotice();

    const unknown = await request(app).post('/recovery/cancel').send({ cancelToken: 'nope' });
    const matched = await request(app).post('/recovery/cancel').send({ cancelToken: token });
    const again = await request(app).post('/recovery/cancel').send({ cancelToken: token });

    expect(unknown.status).toBe(200);
    expect(unknown.body).toEqual(matched.body);
    expect(again.body).toEqual(matched.body);
  });

  it('needs a token', async () => {
    const res = await request(app).post('/recovery/cancel').send({});

    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'cancel_token_required' });
  });
});

describe('decoys', () => {
  const DECOY = decoyPrincipalForSubject(decoySubjectFor('nobody@example.com', 'email'));

  async function answers() {
    return {
      start: await request(app).post('/recovery/start').send({ channel: 'phone' }),
      verify: await request(app).post('/recovery/verify').send({ code: '123456' }),
      status: await request(app).get('/recovery/status'),
      complete: await request(app).post('/recovery/complete'),
    };
  }

  it('answers every ephemeral route the way a real account without a request is answered', async () => {
    principal = realUser({ phone: null, phoneVerified: false });
    const real = await answers();

    decoy = true;
    principal = DECOY as unknown as Record<string, unknown>;
    const fake = await answers();

    for (const key of Object.keys(real) as Array<keyof typeof real>) {
      expect(fake[key].status).toBe(real[key].status);
      expect(fake[key].body).toEqual(real[key].body);
    }
    expect(rows).toHaveLength(0);
  });

  it('never sends a code or a notice for a decoy', async () => {
    decoy = true;
    principal = DECOY as unknown as Record<string, unknown>;

    await request(app).post('/recovery/start').send({ channel: 'email' });
    await request(app).post('/recovery/verify').send({ code: '123456' });

    expect(sendOTPEmail).not.toHaveBeenCalled();
    expect(sendNoticeEmail).not.toHaveBeenCalled();
  });
});
