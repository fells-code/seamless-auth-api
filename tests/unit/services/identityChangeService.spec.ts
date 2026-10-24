import { beforeEach, describe, expect, it, vi } from 'vitest';

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { Session } from '../../../src/models/sessions.js';
import { DeliveryError } from '../../../src/services/deliveryError.js';
import {
  auditIdentityChanges,
  detectIdentityChanges,
  revokeSessionsForIdentityChange,
  sendIdentityChangeNotices,
} from '../../../src/services/identityChangeService.js';
import { sendNoticeEmail, sendNoticeSms } from '../../../src/services/messagingService.js';
import { hashSha256 } from '../../../src/utils/utils.js';

const current = { email: 'old@example.com', phone: '+14155552671' };

beforeEach(() => {
  vi.clearAllMocks();
  (getSystemConfig as any).mockResolvedValue({ app_name: 'Acme' });
});

describe('detectIdentityChanges', () => {
  it('reports a changed email', () => {
    expect(detectIdentityChanges(current, { email: 'new@example.com' })).toEqual([
      { field: 'email', previous: 'old@example.com', next: 'new@example.com' },
    ]);
  });

  it('ignores an email that differs only in case', () => {
    expect(detectIdentityChanges(current, { email: 'OLD@example.com' })).toEqual([]);
  });

  it('reports a changed, removed or added phone', () => {
    expect(detectIdentityChanges(current, { phone: '+14155552672' })).toEqual([
      { field: 'phone', previous: '+14155552671', next: '+14155552672' },
    ]);
    expect(detectIdentityChanges(current, { phone: null })).toEqual([
      { field: 'phone', previous: '+14155552671', next: null },
    ]);
    expect(detectIdentityChanges({ email: null, phone: null }, { phone: '+14155552672' })).toEqual([
      { field: 'phone', previous: null, next: '+14155552672' },
    ]);
  });

  it('ignores an unchanged phone and fields that are not identifiers', () => {
    expect(detectIdentityChanges(current, { phone: '+14155552671', roles: ['admin'] })).toEqual([]);
  });
});

describe('auditIdentityChanges', () => {
  it('records digests of the normalized values rather than the values', () => {
    const audited = auditIdentityChanges([
      { field: 'email', previous: 'Old@Example.com', next: 'new@example.com' },
      { field: 'phone', previous: '+14155552671', next: null },
    ]);

    expect(audited).toEqual([
      {
        field: 'email',
        previousSha256: hashSha256('old@example.com'),
        nextSha256: hashSha256('new@example.com'),
      },
      { field: 'phone', previousSha256: hashSha256('+14155552671'), nextSha256: null },
    ]);
    expect(JSON.stringify(audited)).not.toContain('example.com');
  });
});

describe('revokeSessionsForIdentityChange', () => {
  it('revokes every live session for the user', async () => {
    (Session.update as any).mockResolvedValueOnce([3]);

    await expect(revokeSessionsForIdentityChange('user-1')).resolves.toBe(3);
    expect(Session.update).toHaveBeenCalledWith(
      { revokedAt: expect.any(Date), revokedReason: 'admin_identity_change' },
      { where: { userId: 'user-1', revokedAt: null }, transaction: undefined },
    );
  });
});

describe('sendIdentityChangeNotices', () => {
  it('notifies the previous and the new address', async () => {
    const results = await sendIdentityChangeNotices(
      [
        { field: 'email', previous: 'old@example.com', next: 'new@example.com' },
        { field: 'phone', previous: '+14155552671', next: null },
      ],
      { external: false },
    );

    expect(sendNoticeEmail).toHaveBeenCalledWith(
      'old@example.com',
      'Your Acme sign-in email was changed',
      expect.stringContaining('signed out'),
    );
    expect(sendNoticeEmail).toHaveBeenCalledWith(
      'new@example.com',
      'Your Acme sign-in email was changed',
      expect.stringContaining('set this email address'),
    );
    expect(sendNoticeSms).toHaveBeenCalledTimes(1);
    expect(sendNoticeSms).toHaveBeenCalledWith('+14155552671', expect.stringContaining('phone'));
    expect(results).toEqual([
      { field: 'email', recipient: 'previous', status: 'sent' },
      { field: 'email', recipient: 'new', status: 'sent' },
      { field: 'phone', recipient: 'previous', status: 'sent' },
    ]);
  });

  it('records a failed delivery without throwing', async () => {
    (sendNoticeEmail as any).mockRejectedValueOnce(new DeliveryError('down', new Error('x')));

    const results = await sendIdentityChangeNotices(
      [{ field: 'email', previous: 'old@example.com', next: 'new@example.com' }],
      { external: false },
    );

    expect(results).toEqual([
      { field: 'email', recipient: 'previous', status: 'failed' },
      { field: 'email', recipient: 'new', status: 'sent' },
    ]);
  });

  it('rethrows an error that is not a delivery failure', async () => {
    (sendNoticeEmail as any).mockRejectedValueOnce(new Error('bug'));

    await expect(
      sendIdentityChangeNotices([{ field: 'email', previous: 'old@example.com', next: null }], {
        external: false,
      }),
    ).rejects.toThrow('bug');
  });

  it('sends nothing directly when the caller owns delivery', async () => {
    const results = await sendIdentityChangeNotices(
      [{ field: 'email', previous: 'old@example.com', next: 'new@example.com' }],
      { external: true },
    );

    expect(sendNoticeEmail).not.toHaveBeenCalled();
    expect(results.map((result) => result.status)).toEqual([
      'not_sent_external_delivery',
      'not_sent_external_delivery',
    ]);
  });

  it('falls back to a default app name', async () => {
    (getSystemConfig as any).mockResolvedValueOnce(undefined);

    await sendIdentityChangeNotices([{ field: 'email', previous: null, next: 'new@example.com' }], {
      external: false,
    });

    expect(sendNoticeEmail).toHaveBeenCalledWith(
      'new@example.com',
      'Your Seamless Auth sign-in email was changed',
      expect.any(String),
    );
  });
});
