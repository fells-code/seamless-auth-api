import { describe, expect, it } from 'vitest';

import { sendAccountNotice, verifiedAddresses } from '../../../src/services/accountNotices.js';
import { DeliveryError } from '../../../src/services/deliveryError.js';
import { sendNoticeEmail, sendNoticeSms } from '../../../src/services/messagingService.js';

const notice = { subject: 'Subject', text: 'Body' };
const owner = {
  email: 'owner@example.com',
  emailVerified: true,
  phone: '+14155552671',
  phoneVerified: true,
};

describe('verifiedAddresses', () => {
  it('leaves out an address that is not verified', () => {
    expect(verifiedAddresses({ ...owner, phoneVerified: false })).toEqual({
      email: 'owner@example.com',
      phone: null,
    });
    expect(verifiedAddresses({ email: null, phone: null })).toEqual({ email: null, phone: null });
  });
});

describe('sendAccountNotice', () => {
  it('sends to every verified address', async () => {
    const results = await sendAccountNotice(owner, notice, { external: false });

    expect(sendNoticeEmail).toHaveBeenCalledWith('owner@example.com', 'Subject', 'Body');
    expect(sendNoticeSms).toHaveBeenCalledWith('+14155552671', 'Body');
    expect(results).toEqual([
      { channel: 'email', status: 'sent' },
      { channel: 'phone', status: 'sent' },
    ]);
  });

  it('records a delivery failure without failing', async () => {
    (sendNoticeSms as any).mockRejectedValueOnce(new DeliveryError('down', new Error('down')));

    const results = await sendAccountNotice(owner, notice, { external: false });

    expect(results).toEqual([
      { channel: 'email', status: 'sent' },
      { channel: 'phone', status: 'failed' },
    ]);
  });

  it('rethrows anything that is not a delivery failure', async () => {
    (sendNoticeEmail as any).mockRejectedValueOnce(new Error('bug'));

    await expect(sendAccountNotice(owner, notice, { external: false })).rejects.toThrow('bug');
  });

  it('sends nothing to a caller that owns delivery, and says so', async () => {
    const results = await sendAccountNotice(owner, notice, { external: true });

    expect(sendNoticeEmail).not.toHaveBeenCalled();
    expect(results).toEqual([
      { channel: 'email', status: 'not_sent_external_delivery' },
      { channel: 'phone', status: 'not_sent_external_delivery' },
    ]);
  });
});
