import { describe, expect, it, vi } from 'vitest';

import {
  ownerWasNotified,
  sendAccountNotice,
  verifiedAddresses,
} from '../../../src/services/accountNotices.js';
import { DeliveryError } from '../../../src/services/deliveryError.js';
import {
  canSendNoticeDirectly,
  sendNoticeEmail,
  sendNoticeSms,
} from '../../../src/services/messagingService.js';

const notice = {
  name: 'account_recovery_opened' as const,
  subject: 'Subject',
  text: 'Body',
  cancelUrl: 'https://app.example.com/recovery/cancel#t',
};
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
    const { results } = await sendAccountNotice(owner, notice, { external: false });

    expect(sendNoticeEmail).toHaveBeenCalledWith('owner@example.com', 'Subject', 'Body');
    expect(sendNoticeSms).toHaveBeenCalledWith('+14155552671', 'Body');
    expect(results).toEqual([
      { channel: 'email', status: 'sent' },
      { channel: 'phone', status: 'sent' },
    ]);
  });

  it('records a delivery failure without failing', async () => {
    (sendNoticeSms as any).mockRejectedValueOnce(new DeliveryError('down', new Error('down')));

    const { results } = await sendAccountNotice(owner, notice, { external: false });

    expect(results).toEqual([
      { channel: 'email', status: 'sent' },
      { channel: 'phone', status: 'failed' },
    ]);
  });

  it('rethrows anything that is not a delivery failure', async () => {
    (sendNoticeEmail as any).mockRejectedValueOnce(new Error('bug'));

    await expect(sendAccountNotice(owner, notice, { external: false })).rejects.toThrow('bug');
  });

  it('sends directly what a caller that owns delivery does not take', async () => {
    const outcome = await sendAccountNotice(owner, notice, { external: true });

    expect(sendNoticeEmail).toHaveBeenCalledWith('owner@example.com', 'Subject', 'Body');
    expect(sendNoticeSms).toHaveBeenCalledWith('+14155552671', 'Body');
    expect(outcome).toEqual({
      results: [
        { channel: 'email', status: 'sent' },
        { channel: 'phone', status: 'sent' },
      ],
      deliveries: [],
    });
  });

  it('sends nothing for a caller that owns delivery when the API has no transport, and says so', async () => {
    vi.mocked(canSendNoticeDirectly).mockReturnValue(false);

    const outcome = await sendAccountNotice(owner, notice, { external: true });

    expect(sendNoticeEmail).not.toHaveBeenCalled();
    expect(outcome).toEqual({
      results: [
        { channel: 'email', status: 'not_sent_external_delivery' },
        { channel: 'phone', status: 'not_sent_external_delivery' },
      ],
      deliveries: [],
    });
    expect(ownerWasNotified(outcome)).toBe(false);
  });

  it('hands a notice back only in the kinds the caller accepts, and sends the rest', async () => {
    const outcome = await sendAccountNotice(owner, notice, {
      external: true,
      returnable: new Set(['account_notice_email']),
    });

    expect(sendNoticeEmail).not.toHaveBeenCalled();
    expect(sendNoticeSms).toHaveBeenCalledWith('+14155552671', 'Body');
    expect(outcome.results).toEqual([
      { channel: 'email', status: 'returned_for_external_delivery' },
      { channel: 'phone', status: 'sent' },
    ]);
    expect(outcome.deliveries).toEqual([
      {
        kind: 'account_notice_email',
        notice: 'account_recovery_opened',
        to: 'owner@example.com',
        subject: 'Subject',
        text: 'Body',
        cancelUrl: 'https://app.example.com/recovery/cancel#t',
      },
    ]);
    expect(ownerWasNotified(outcome)).toBe(true);
  });

  it('builds an SMS notice without a subject, and leaves out an absent cancel link', async () => {
    const { deliveries } = await sendAccountNotice(
      { ...owner, emailVerified: false },
      { name: 'recovery_code_used', subject: 'Subject', text: 'Body' },
      { external: true, returnable: new Set(['account_notice_sms']) },
    );

    expect(deliveries).toEqual([
      {
        kind: 'account_notice_sms',
        notice: 'recovery_code_used',
        to: '+14155552671',
        text: 'Body',
      },
    ]);
  });

  it('never returns a notice to a caller sending directly, even if it lists kinds', async () => {
    const outcome = await sendAccountNotice(owner, notice, {
      external: false,
      returnable: new Set(['account_notice_email', 'account_notice_sms']),
    });

    expect(outcome.deliveries).toEqual([]);
    expect(sendNoticeEmail).toHaveBeenCalled();
  });
});
