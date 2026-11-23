/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { createHmac, timingSafeEqual } from 'crypto';
import { QueryTypes, Transaction } from 'sequelize';

import { getSequelize } from '../models/index.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('auditHeadSignature');

type EnvSource = Record<string, string | undefined>;

export function auditChainKey(env: EnvSource = process.env): string | null {
  return env.AUDIT_CHAIN_KEY?.trim() || null;
}

export function warnIfAuditChainKeyUnset(env: EnvSource = process.env) {
  if (env.NODE_ENV === 'production' && !auditChainKey(env)) {
    logger.warn(
      'AUDIT_CHAIN_KEY is not set, so the audit chain head is not signed and a role that can ' +
        'delete the newest audit events can hide that it did. See docs/security-posture.md.',
    );
  }
}

// The migration that adds the signature columns signs the head in this same format, so
// the two must change together.
export function signAuditHead(key: string, seq: number, hash: string | null): string {
  return createHmac('sha256', key)
    .update(`seamless-audit-head:v1:${seq}:${hash ?? ''}`)
    .digest('hex');
}

export function auditHeadSignatureValid(
  key: string,
  seq: number,
  hash: string | null,
  signature: string | null,
): boolean {
  if (!signature) return false;

  const expected = Buffer.from(signAuditHead(key, seq, hash), 'hex');
  const given = Buffer.from(signature, 'hex');

  return given.length === expected.length && timingSafeEqual(given, expected);
}

type SignedHeadRow = {
  signed_seq: string | null;
  signature: string | null;
  signed_hash: string | null;
};

let warnedUnverifiable = false;

/**
 * Moves the head signature onto a row this transaction just inserted.
 *
 * Runs while the insert still holds the chain head row lock, so no other insert can move
 * the head in between. It only signs forward from a signature that verifies: a head that
 * is unsigned, or whose signature is wrong, stays that way, because signing over it would
 * erase the evidence that it was changed. `sealAuditChainHead` is how an operator signs
 * such a head again.
 */
export async function signInsertedAuditHead(
  event: { seq?: string | number | null; hash?: string | null; prev_hash?: string | null },
  transaction: Transaction,
  key: string,
): Promise<boolean> {
  if (event.seq === null || event.seq === undefined || !event.hash) return false;

  const seq = Number(event.seq);
  const signature = signAuditHead(key, seq, event.hash);
  const sequelize = getSequelize();

  const advanced = await sequelize.query(
    `UPDATE public.auth_event_chain_head
       SET signed_seq = :seq, signature = :signature
       WHERE id = 1 AND signed_seq = :prevSeq AND signature = :prevSignature
       RETURNING signed_seq`,
    {
      replacements: {
        seq,
        signature,
        prevSeq: seq - 1,
        prevSignature: signAuditHead(key, seq - 1, event.prev_hash ?? null),
      },
      transaction,
      type: QueryTypes.SELECT,
    },
  );

  if (advanced.length > 0) return true;

  // The signature lags the head when an insert ran without the key, so it is checked
  // against the row it was made for rather than the one just before this insert.
  const [current] = await sequelize.query<SignedHeadRow>(
    `SELECT h.signed_seq, h.signature, e.hash AS signed_hash
       FROM public.auth_event_chain_head h
       LEFT JOIN public.auth_events e ON e.seq = h.signed_seq
       WHERE h.id = 1`,
    { transaction, type: QueryTypes.SELECT },
  );

  const signedSeq = current?.signed_seq ? Number(current.signed_seq) : null;

  if (
    signedSeq === null ||
    signedSeq >= seq ||
    !auditHeadSignatureValid(key, signedSeq, current.signed_hash, current.signature)
  ) {
    if (!warnedUnverifiable) {
      warnedUnverifiable = true;
      logger.error(
        'The audit chain head signature does not verify, so new events are not being signed. ' +
          'Check GET /admin/auth-events/integrity, then sign the head again with ' +
          'node dist/scripts/sealAuditHead.js. See docs/security-posture.md.',
      );
    }
    return false;
  }

  await sequelize.query(
    `UPDATE public.auth_event_chain_head
       SET signed_seq = :seq, signature = :signature
       WHERE id = 1 AND signed_seq = :signedSeq`,
    { replacements: { seq, signature, signedSeq }, transaction },
  );

  return true;
}
